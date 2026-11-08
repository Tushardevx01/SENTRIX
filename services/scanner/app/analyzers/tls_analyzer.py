import ssl
import socket
import hashlib
from datetime import datetime, timezone
from typing import Tuple, List, Optional, Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.x509.oid import ExtensionOID
from app.schemas.response import RawFinding, CertificateInfo
from app.safety.ssrf_guard import resolve_and_validate_hostname, SSRFSecurityException

# Known untrusted, compromised, or high-risk Certificate Authorities
# Includes eMudhra sub-CAs affected by flawed PRNG/key generation incidents,
# as well as revoked/distrusted roots (WoSign, StartCom, Camerfirma, DigiNotar, DarkMatter/TrustCor, Symantec legacy)
DISTRUSTED_CA_PATTERNS = [
    ("emudhra", "eMudhra Subordinate CA / Flawed Key Generation Incident Risk", "HIGH"),
    ("wosign", "WoSign (Distrusted by Major Root Stores)", "CRITICAL"),
    ("startcom", "StartCom (Distrusted by Major Root Stores)", "CRITICAL"),
    ("camerfirma", "AC Camerfirma (Revoked Root Trust)", "CRITICAL"),
    ("diginotar", "DigiNotar (Compromised & Permanently Revoked CA)", "CRITICAL"),
    ("trustcor", "TrustCor Systems (Distrusted Root Authority)", "HIGH"),
    ("darkmatter", "DarkMatter / CyberPoint (Untrusted PKI Authority)", "HIGH"),
]


def get_max_validity_days_sc081v3(not_before: datetime) -> int:
    """
    Returns the maximum allowable validity duration in days under CA/Browser Forum
    Ballot SC-081v3 schedule for publicly-trusted TLS subscriber certificates based on
    certificate issuance timestamp (notBefore).

    Schedule:
    - Before 15 March 2026 (post-Sept 1, 2020): 398 days
    - 15 March 2026 to 14 March 2027: 200 days
    - 15 March 2027 to 14 March 2029: 100 days
    - From 15 March 2029: 47 days
    """
    # From 15 March 2029 00:00:00 UTC: maximum 47 days
    if not_before >= datetime(2029, 3, 15, tzinfo=timezone.utc):
        return 47
    # 15 March 2027 00:00:00 UTC to 14 March 2029 23:59:59 UTC: maximum 100 days
    elif not_before >= datetime(2027, 3, 15, tzinfo=timezone.utc):
        return 100
    # 15 March 2026 00:00:00 UTC to 14 March 2027 23:59:59 UTC: maximum 200 days
    elif not_before >= datetime(2026, 3, 15, tzinfo=timezone.utc):
        return 200
    # Before 15 March 2026 (post-September 1, 2020): maximum 398 days
    elif not_before >= datetime(2020, 9, 1, tzinfo=timezone.utc):
        return 398
    else:
        # Prior to September 1, 2020: 825 days under earlier CA/B Forum guidelines
        return 825


class TlsAnalyzer:
    """
    Inspects TLS/SSL certificate health, certificate chain authenticity,
    cryptographic expiration, and hostname validation using strict verification.
    """

    def analyze(
        self,
        hostname: str,
        port: int = 443,
        target_ip: Optional[str] = None
    ) -> Tuple[List[RawFinding], Optional[CertificateInfo]]:
        findings: List[RawFinding] = []
        cert_info: Optional[CertificateInfo] = None

        # Pre-flight destination IP resolution & SSRF validation if not provided
        connect_ip = target_ip
        if not connect_ip:
            try:
                resolved = resolve_and_validate_hostname(hostname, port)
                connect_ip = resolved[0]
            except SSRFSecurityException as e:
                findings.append(RawFinding(
                    category="TLS_SECURITY",
                    severity="CRITICAL",
                    title="TLS Connection Prohibited by Security Policy",
                    description=str(e),
                    evidence={"hostname": hostname, "port": port},
                    confidence=100.0,
                ))
                return findings, None

        # 1. Attempt strict TLS connection with hostname verification & trusted CA requirements
        strict_ctx = ssl.create_default_context()
        strict_ctx.check_hostname = True
        strict_ctx.verify_mode = ssl.CERT_REQUIRED

        hostname_matched = True
        verification_error: Optional[str] = None
        cert_dict = {}
        der_cert: Optional[bytes] = None

        try:
            with socket.create_connection((connect_ip, port), timeout=5.0) as sock:
                with strict_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert(binary_form=False) or {}
        except ssl.SSLCertVerificationError as e:
            verification_error = str(getattr(e, "verify_message", None) or e)
            hostname_matched = False
            error_code = getattr(e, "verify_code", None)

            # Classify specific TLS failure
            err_lower = verification_error.lower()
            if "expired" in err_lower or "certificate has expired" in err_lower:
                findings.append(RawFinding(
                    category="TLS_SECURITY",
                    severity="CRITICAL",
                    title="Expired SSL/TLS Certificate",
                    description="The target server presents an expired TLS certificate. Encrypted communication cannot be trusted.",
                    evidence={"error": verification_error, "code": error_code},
                    confidence=95.0,
                ))
            elif "self-signed" in err_lower or "self signed" in err_lower:
                findings.append(RawFinding(
                    category="TLS_SECURITY",
                    severity="HIGH",
                    title="Self-Signed SSL/TLS Certificate",
                    description="The server certificate is self-signed or issued by an untrusted authority.",
                    evidence={"error": verification_error, "code": error_code},
                    confidence=95.0,
                ))
            elif "hostname" in err_lower or "doesn't match" in err_lower or "does not match" in err_lower:
                findings.append(RawFinding(
                    category="TLS_SECURITY",
                    severity="HIGH",
                    title="TLS Certificate Hostname Mismatch",
                    description=f"The certificate presented does not match the requested destination host '{hostname}'.",
                    evidence={"error": verification_error, "requestedHost": hostname},
                    confidence=95.0,
                ))
            else:
                findings.append(RawFinding(
                    category="TLS_SECURITY",
                    severity="HIGH",
                    title="TLS Certificate Chain Verification Failed",
                    description=f"TLS certificate verification failed: {verification_error}",
                    evidence={"error": verification_error, "code": error_code},
                    confidence=90.0,
                ))

            # Retrieve certificate details for forensic reporting via unverified handshake (never used for web traffic!)
            try:
                unverified_ctx = ssl.create_default_context()
                unverified_ctx.check_hostname = False
                unverified_ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((connect_ip, port), timeout=4.0) as sock:
                    with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                        cert_dict = ssock.getpeercert(binary_form=False) or {}
            except Exception:
                pass

        except (socket.timeout, TimeoutError):
            findings.append(RawFinding(
                category="TLS_SECURITY",
                severity="INFO",
                title="TLS Connection Timed Out",
                description=f"Connection to {hostname}:{port} timed out during TLS handshake.",
                evidence={"hostname": hostname, "port": port},
                confidence=70.0,
            ))
            return findings, None

        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            findings.append(RawFinding(
                category="TLS_SECURITY",
                severity="INFO",
                title="TLS Service Unreachable on Port 443",
                description=f"Target host refused or failed TCP connection on port {port} ({type(e).__name__}).",
                evidence={"error": str(e), "port": port},
                confidence=80.0,
            ))
            return findings, None

        if not der_cert:
            if not findings:
                findings.append(RawFinding(
                    category="TLS_SECURITY",
                    severity="HIGH",
                    title="No TLS Certificate Presented",
                    description="Target server did not supply an X.509 certificate during TLS handshake.",
                    evidence={"hostname": hostname, "port": port},
                    confidence=90.0,
                ))
            return findings, None

        # 2. Extract and parse certificate details
        sha256_fp = hashlib.sha256(der_cert).hexdigest()

        not_before_str = cert_dict.get("notBefore", "")
        not_after_str = cert_dict.get("notAfter", "")
        valid_from_iso = ""
        valid_until_iso = ""

        try:
            if not_before_str:
                dt_from = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                valid_from_iso = dt_from.isoformat()
            if not_after_str:
                dt_until = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                valid_until_iso = dt_until.isoformat()

                now = datetime.now(timezone.utc)
                if dt_until < now:
                    if not any(f.title == "Expired SSL/TLS Certificate" for f in findings):
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="CRITICAL",
                            title="Expired SSL/TLS Certificate",
                            description="The target site presents an expired SSL/TLS certificate.",
                            evidence={"validUntil": valid_until_iso, "expiredDays": (now - dt_until).days},
                            confidence=100.0,
                        ))
                elif (dt_until - now).days < 14:
                    findings.append(RawFinding(
                        category="TLS_SECURITY",
                        severity="MEDIUM",
                        title="TLS Certificate Expiring Soon",
                        description=f"The TLS certificate will expire in {(dt_until - now).days} days.",
                        evidence={"daysRemaining": (dt_until - now).days},
                        confidence=80.0,
                    ))
        except Exception:
            valid_from_iso = not_before_str
            valid_until_iso = not_after_str

        issuer_parts = [f"{k}={v}" for item in cert_dict.get("issuer", ()) for k, v in item]
        subject_parts = [f"{k}={v}" for item in cert_dict.get("subject", ()) for k, v in item]
        issuer_str = ", ".join(issuer_parts) or "Unknown CA"
        subject_str = ", ".join(subject_parts) or hostname

        # Self-signed indicator
        if issuer_str == subject_str and issuer_str != "Unknown CA":
            if not any("Self-Signed" in f.title for f in findings):
                findings.append(RawFinding(
                    category="TLS_SECURITY",
                    severity="HIGH",
                    title="Self-Signed TLS Certificate",
                    description="The certificate issuer matches the subject, indicating a self-signed certificate.",
                    evidence={"issuer": issuer_str, "subject": subject_str},
                    confidence=95.0,
                ))

        san_entries = [entry[1] for entry in cert_dict.get("subjectAltName", ()) if entry[0] == "DNS"]
        cn = ""
        for item in cert_dict.get("subject", ()):
            for k, v in item:
                if k == "commonName":
                    cn = v

        # Hostname matching check: verify hostname against CN and SANs
        if hostname_matched and (san_entries or cn):
            host_lower = hostname.lower()
            matched = False
            for san in san_entries:
                san_clean = san.lower()
                if san_clean == host_lower or (san_clean.startswith("*.") and host_lower.endswith(san_clean[1:])):
                    matched = True
                    break
            if not matched and cn:
                cn_clean = cn.lower()
                if cn_clean == host_lower or (cn_clean.startswith("*.") and host_lower.endswith(cn_clean[1:])):
                    matched = True

            if not matched:
                hostname_matched = False
                if not any("Hostname Mismatch" in f.title for f in findings):
                    findings.append(RawFinding(
                        category="TLS_SECURITY",
                        severity="HIGH",
                        title="TLS Certificate Hostname Mismatch",
                        description=f"The certificate presented does not match the requested destination host '{hostname}'.",
                        evidence={"requestedHost": hostname, "commonName": cn, "subjectAltNames": san_entries},
                        confidence=95.0,
                    ))

        # 3. Deep Cryptographic & Certificate Authority Inspection via cryptography.x509
        key_algorithm = "Unknown"
        key_size = 0
        signature_algorithm = "Unknown"
        has_scts = False
        is_ca = False
        validity_days = 0
        compromised_ca_risk = False

        if der_cert:
            try:
                x509_cert = x509.load_der_x509_certificate(der_cert)

                # Public Key Algorithm & Key Size Audit
                pub_key = x509_cert.public_key()
                if isinstance(pub_key, rsa.RSAPublicKey):
                    key_algorithm = "RSA"
                    key_size = pub_key.key_size
                    if key_size < 2048:
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="CRITICAL",
                            title="Insecure Cryptographic Key Length (RSA < 2048 bits)",
                            description=f"The certificate uses an insecure {key_size}-bit RSA key. Sub-2048 bit keys are vulnerable to mathematical factorization attacks and violate CA/B Forum guidelines.",
                            evidence={"keyAlgorithm": "RSA", "keySize": key_size},
                            confidence=98.0,
                        ))
                    elif key_size == 2048:
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="INFO",
                            title="Standard RSA 2048-bit Public Key",
                            description="The certificate uses a standard 2048-bit RSA public key meeting baseline cryptographic requirements.",
                            evidence={"keyAlgorithm": "RSA", "keySize": key_size},
                            confidence=100.0,
                        ))
                    elif key_size >= 3072:
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="INFO",
                            title="High-Strength RSA Public Key",
                            description=f"The certificate uses a high-assurance {key_size}-bit RSA key providing robust forward security.",
                            evidence={"keyAlgorithm": "RSA", "keySize": key_size},
                            confidence=100.0,
                        ))
                elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                    curve_name = pub_key.curve.name
                    key_algorithm = f"ECDSA ({curve_name})"
                    key_size = pub_key.key_size
                    if key_size < 256:
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="HIGH",
                            title="Weak Elliptic Curve Key (< 256 bits)",
                            description=f"The certificate uses a weak elliptic curve ({curve_name}) with {key_size} bits of security.",
                            evidence={"curve": curve_name, "keySize": key_size},
                            confidence=95.0,
                        ))
                    else:
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="INFO",
                            title="Modern Elliptic Curve (ECDSA) Key",
                            description=f"The certificate uses a modern {key_size}-bit elliptic curve key ({curve_name}).",
                            evidence={"curve": curve_name, "keySize": key_size},
                            confidence=100.0,
                        ))
                elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                    key_algorithm = "Ed25519"
                    key_size = 256
                    findings.append(RawFinding(
                        category="TLS_SECURITY",
                        severity="INFO",
                        title="High-Performance Ed25519 Public Key",
                        description="The certificate utilizes Ed25519 modern Edwards-curve public key cryptography.",
                        evidence={"keyAlgorithm": "Ed25519"},
                        confidence=100.0,
                    ))
                elif isinstance(pub_key, dsa.DSAPublicKey):
                    key_algorithm = "DSA"
                    key_size = pub_key.key_size
                    findings.append(RawFinding(
                        category="TLS_SECURITY",
                        severity="HIGH",
                        title="Deprecated DSA Key Algorithm",
                        description="The certificate uses the legacy DSA public key algorithm which is widely deprecated in TLS.",
                        evidence={"keyAlgorithm": "DSA", "keySize": key_size},
                        confidence=95.0,
                    ))

                # Signature Algorithm Analysis
                try:
                    signature_algorithm = x509_cert.signature_algorithm_oid._name or "Unknown"
                except Exception:
                    signature_algorithm = str(x509_cert.signature_algorithm_oid)

                sig_lower = signature_algorithm.lower()
                if "sha1" in sig_lower or "md5" in sig_lower or "md2" in sig_lower:
                    findings.append(RawFinding(
                        category="TLS_SECURITY",
                        severity="CRITICAL",
                        title="Cryptographically Broken Certificate Signature Algorithm",
                        description=f"The certificate was signed using {signature_algorithm}. Collision attacks allow adversaries to forge fraudulent certificates sharing this hash.",
                        evidence={"signatureAlgorithm": signature_algorithm},
                        confidence=98.0,
                    ))

                # Certificate Transparency (CT) Signed Certificate Timestamps (SCTs)
                has_scts = False
                try:
                    x509_cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
                    has_scts = True
                except x509.ExtensionNotFound:
                    try:
                        x509_cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3"))
                        has_scts = True
                    except Exception:
                        has_scts = False

                if has_scts:
                    findings.append(RawFinding(
                        category="TLS_SECURITY",
                        severity="INFO",
                        title="Embedded Certificate Transparency (CT) Timestamps Present",
                        description="The certificate embeds Signed Certificate Timestamps (SCTs) within its X.509 extensions, confirming CT log inclusion.",
                        evidence={"hasEmbeddedSCTs": True, "inspectedSource": "leaf_x509_extensions"},
                        confidence=100.0,
                    ))
                elif issuer_str != subject_str and verification_error is None:
                    # Distinguish absence of embedded SCTs from confirmed non-compliance (SCTs may be in TLS handshake or OCSP)
                    findings.append(RawFinding(
                        category="TLS_SECURITY",
                        severity="LOW",
                        title="No Embedded Certificate Transparency (CT) SCTs in Leaf Certificate",
                        description="The leaf certificate does not embed Signed Certificate Timestamps (SCTs) within its X.509 extensions. Note: Public CAs frequently deliver SCTs out-of-band via TLS extension handshake or OCSP stapling; absence in the leaf certificate alone does not confirm non-compliance.",
                        evidence={
                            "hasEmbeddedSCTs": False,
                            "inspectedSource": "leaf_x509_extensions",
                            "alternateDeliveryMethods": ["tls_handshake_extension", "ocsp_stapling"],
                            "note": "Complete CT verification requires inspecting TLS handshake extensions and OCSP stapled responses.",
                            "isPosture": True,
                            "dedupKey": "POSTURE_MISSING_SCT",
                        },
                        confidence=80.0,
                    ))

                # Basic Constraints Check (Leaf certificate cannot be CA)
                try:
                    bc_ext = x509_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                    is_ca = bc_ext.value.ca
                    if is_ca:
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="CRITICAL",
                            title="Leaf Certificate Configured as Certificate Authority (CA: TRUE)",
                            description="The end-entity certificate has the Basic Constraints CA flag set to TRUE, presenting a severe risk where the holder could sign valid subordinate certificates for arbitrary domains.",
                            evidence={"isCA": True},
                            confidence=99.0,
                        ))
                except x509.ExtensionNotFound:
                    is_ca = False

                # CA/Browser Forum SC-081v3 Validity Duration Policy Check
                # Applies strictly to public TLS subscriber certificates (non-CA, non-self-signed)
                try:
                    not_before = getattr(x509_cert, "not_valid_before_utc", None) or x509_cert.not_valid_before.replace(tzinfo=timezone.utc)
                    not_after = getattr(x509_cert, "not_valid_after_utc", None) or x509_cert.not_valid_after.replace(tzinfo=timezone.utc)
                    validity_days = (not_after - not_before).days
                    baseline_cutoff = datetime(2020, 9, 1, tzinfo=timezone.utc)

                    # Only evaluate public subscriber certificates (not self-signed, not a CA)
                    if issuer_str != subject_str and not is_ca and not_before >= baseline_cutoff:
                        max_allowed_days = get_max_validity_days_sc081v3(not_before)
                        if validity_days > max_allowed_days:
                            findings.append(RawFinding(
                                category="TLS_SECURITY",
                                severity="MEDIUM",
                                title=f"Non-Compliant Certificate Validity Duration ({validity_days} days > {max_allowed_days} days)",
                                description=(
                                    f"The certificate validity spans {validity_days} days, exceeding the CA/Browser Forum "
                                    f"Ballot SC-081v3 maximum allowable limit of {max_allowed_days} days for subscriber "
                                    f"certificates issued on {not_before.strftime('%Y-%m-%d')}."
                                ),
                                evidence={
                                    "issuanceDate": not_before.isoformat(),
                                    "expirationDate": not_after.isoformat(),
                                    "calculatedLifetimeDays": validity_days,
                                    "maxAllowedDays": max_allowed_days,
                                    "policyReference": "CA/Browser Forum Ballot SC-081v3 (Baseline Requirements Section 6.3.2)",
                                    "scope": "Public TLS Subscriber Certificate",
                                },
                                confidence=95.0,
                            ))
                except Exception:
                    pass

            except Exception:
                # Fallback gracefully if cryptography parsing fails
                pass

        # 4. Compromised / Distrusted / High-Risk Certificate Authority Detection
        issuer_lower = issuer_str.lower()
        for ca_term, ca_name, severity in DISTRUSTED_CA_PATTERNS:
            if ca_term in issuer_lower:
                compromised_ca_risk = True
                if issuer_str == subject_str:
                    # Self-signed certificate mimicking a distrusted CA name
                    findings.append(RawFinding(
                        category="TLS_SECURITY",
                        severity="HIGH",
                        title=f"Self-Signed Certificate Claiming Distrusted CA Name: {ca_name}",
                        description=(
                            f"The certificate is self-signed and contains '{issuer_str}', mimicking the name of "
                            f"distrusted CA '{ca_name}'. This indicates an adversary mimicking CA identifiers in an "
                            f"unverified self-signed certificate, rather than authentic issuance."
                        ),
                        evidence={
                            "issuer": issuer_str,
                            "subject": subject_str,
                            "flaggedCA": ca_name,
                            "pattern": ca_term,
                            "isSelfSigned": True,
                            "verifiedChain": False,
                        },
                        confidence=95.0,
                    ))
                elif verification_error is not None:
                    # Issuer name pattern match on an unverified certificate chain
                    findings.append(RawFinding(
                        category="TLS_SECURITY",
                        severity="HIGH",
                        title=f"Distrusted CA Name Pattern Match (Unverified Chain): {ca_name}",
                        description=(
                            f"The certificate issuer matches known problematic CA '{ca_name}', but chain verification "
                            f"failed ({verification_error}). This is an unverified name pattern match, not proof of "
                            f"cryptographic root signature."
                        ),
                        evidence={
                            "issuer": issuer_str,
                            "flaggedCA": ca_name,
                            "pattern": ca_term,
                            "verificationError": verification_error,
                            "verifiedChain": False,
                        },
                        confidence=90.0,
                    ))
                else:
                    # Verified root store signature from distrusted CA
                    findings.append(RawFinding(
                        category="TLS_SECURITY",
                        severity=severity,
                        title=f"Compromised / High-Risk Certificate Authority: {ca_name}",
                        description=(
                            f"The certificate is signed by '{issuer_str}', matching known problematic CA authority "
                            f"'{ca_name}'. This authority is distrusted by root stores or subject to critical revocation."
                        ),
                        evidence={
                            "issuer": issuer_str,
                            "flaggedCA": ca_name,
                            "pattern": ca_term,
                            "verifiedChain": True,
                        },
                        confidence=95.0,
                    ))

        cert_info = CertificateInfo(
            issuer=issuer_str,
            subject=subject_str,
            validFrom=valid_from_iso or datetime.now(timezone.utc).isoformat(),
            validUntil=valid_until_iso or datetime.now(timezone.utc).isoformat(),
            fingerprint=sha256_fp,
            hostnameMatched=hostname_matched,
            rawDetails={
                "serialNumber": cert_dict.get("serialNumber"),
                "subjectAltName": san_entries[:10],
                "verified": (verification_error is None),
                "keyAlgorithm": key_algorithm,
                "keySize": key_size,
                "signatureAlgorithm": signature_algorithm,
                "hasSCTs": has_scts,
                "isCa": is_ca,
                "validityDays": validity_days,
                "compromisedCaRisk": compromised_ca_risk,
            },
        )

        # If completely valid with no findings
        if hostname_matched and not findings and not verification_error:
            findings.append(RawFinding(
                category="TLS_SECURITY",
                severity="INFO",
                title="Valid TLS Certificate",
                description="The destination presents an unexpired TLS certificate issued by a trusted authority matching the hostname.",
                evidence={"issuer": issuer_str, "fingerprint": sha256_fp[:16] + "..."},
                confidence=100.0,
            ))

        return findings, cert_info

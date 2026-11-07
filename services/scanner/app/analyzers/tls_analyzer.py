import ssl
import socket
import hashlib
from datetime import datetime, timezone
from typing import Tuple, List, Optional
from app.schemas.response import RawFinding, CertificateInfo
from app.safety.ssrf_guard import resolve_and_validate_hostname, SSRFSecurityException


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
            verification_error = str(e.verify_message or e)
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

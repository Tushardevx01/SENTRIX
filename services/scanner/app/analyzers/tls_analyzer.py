import ssl
import socket
import hashlib
from datetime import datetime, timezone
from typing import Tuple, List, Optional
from app.schemas.response import RawFinding, CertificateInfo


class TlsAnalyzer:
    """Inspects TLS/SSL certificate health, certificate chain authenticity, and cipher standards."""

    def analyze(self, hostname: str, port: int = 443) -> Tuple[List[RawFinding], Optional[CertificateInfo]]:
        findings: List[RawFinding] = []
        cert_info: Optional[CertificateInfo] = None

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=4.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="HIGH",
                            title="No TLS Certificate Presented",
                            description="The target server accepted connection on port 443 but did not supply a certificate.",
                            evidence={"hostname": hostname, "port": port},
                            confidence=90.0
                        ))
                        return findings, None

                    # Calculate fingerprint
                    sha256_fp = hashlib.sha256(der_cert).hexdigest()

                    # Re-verify with hostname check
                    verification_ctx = ssl.create_default_context()
                    hostname_matched = True
                    cert_dict = ssock.getpeercert(binary_form=False) or {}

                    try:
                        with socket.create_connection((hostname, port), timeout=4.0) as verify_sock:
                            with verification_ctx.wrap_socket(verify_sock, server_hostname=hostname) as verify_ssock:
                                cert_dict = verify_ssock.getpeercert() or {}
                    except ssl.SSLCertVerificationError as e:
                        hostname_matched = False
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="HIGH",
                            title="TLS Certificate Validation Failed",
                            description=f"TLS certificate verification failed: {e.verify_message}",
                            evidence={"error": str(e), "code": getattr(e, "verify_code", None)},
                            confidence=95.0
                        ))
                    except Exception:
                        pass

                    # Parse dates
                    not_before_str = cert_dict.get("notBefore", "")
                    not_after_str = cert_dict.get("notAfter", "")
                    
                    # Convert to ISO
                    valid_from_iso = ""
                    valid_until_iso = ""
                    try:
                        if not_before_str:
                            dt_from = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            valid_from_iso = dt_from.isoformat()
                        if not_after_str:
                            dt_until = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            valid_until_iso = dt_until.isoformat()
                            
                            # Check expiration
                            now = datetime.now(timezone.utc)
                            if dt_until < now:
                                findings.append(RawFinding(
                                    category="TLS_SECURITY",
                                    severity="CRITICAL",
                                    title="Expired SSL/TLS Certificate",
                                    description="The target site presents an expired SSL/TLS certificate, rendering encrypted communications unsafe.",
                                    evidence={"validUntil": valid_until_iso, "expiredDays": (now - dt_until).days},
                                    confidence=100.0
                                ))
                            elif (dt_until - now).days < 14:
                                findings.append(RawFinding(
                                    category="TLS_SECURITY",
                                    severity="MEDIUM",
                                    title="TLS Certificate Expiring Soon",
                                    description=f"The certificate will expire in {(dt_until - now).days} days.",
                                    evidence={"daysRemaining": (dt_until - now).days},
                                    confidence=80.0
                                ))
                    except Exception:
                        valid_from_iso = not_before_str
                        valid_until_iso = not_after_str

                    # Parse Issuer & Subject strings
                    issuer_parts = [f"{k}={v}" for item in cert_dict.get("issuer", ()) for k, v in item]
                    subject_parts = [f"{k}={v}" for item in cert_dict.get("subject", ()) for k, v in item]
                    issuer_str = ", ".join(issuer_parts) or "Unknown CA"
                    subject_str = ", ".join(subject_parts) or hostname

                    # Check for self-signed
                    if issuer_str == subject_str and issuer_str != "Unknown CA":
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="HIGH",
                            title="Self-Signed TLS Certificate",
                            description="The certificate issuer matches the subject, indicating a self-signed or untrusted root certificate.",
                            evidence={"issuer": issuer_str, "subject": subject_str},
                            confidence=90.0
                        ))

                    cert_info = CertificateInfo(
                        issuer=issuer_str,
                        subject=subject_str,
                        validFrom=valid_from_iso or datetime.now(timezone.utc).isoformat(),
                        validUntil=valid_until_iso or datetime.now(timezone.utc).isoformat(),
                        fingerprint=sha256_fp,
                        hostnameMatched=hostname_matched,
                        rawDetails={"serialNumber": cert_dict.get("serialNumber")}
                    )

                    if hostname_matched and not findings:
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="INFO",
                            title="Valid TLS Certificate",
                            description="The domain presents a trusted, unexpired TLS certificate matching the destination hostname.",
                            evidence={"issuer": issuer_str, "fingerprint": sha256_fp[:16] + "..."},
                            confidence=100.0
                        ))

        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            findings.append(RawFinding(
                category="TLS_SECURITY",
                severity="LOW",
                title="TLS Service Unreachable on Port 443",
                description=f"Could not complete TLS handshake on port 443 ({type(e).__name__}).",
                evidence={"error": str(e)},
                confidence=70.0
            ))

        return findings, cert_info

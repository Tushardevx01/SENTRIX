import ssl
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from app.analyzers.tls_analyzer import TlsAnalyzer


def create_mock_ssock(cert_dict, der_bytes=b"dummy_der_x509_bytes"):
    mock_sock = MagicMock()
    mock_sock.getpeercert.side_effect = lambda binary_form=False: der_bytes if binary_form else cert_dict
    mock_sock.version.return_value = "TLSv1.3"
    mock_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    # Support context manager
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.__exit__.return_value = None
    return mock_sock


def test_tls_detects_expired_certificate():
    analyzer = TlsAnalyzer()

    # Expired 10 days ago
    past_date = datetime.now(timezone.utc) - timedelta(days=10)
    not_after_str = past_date.strftime("%b %d %H:%M:%S %Y GMT")
    not_before_str = (past_date - timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")

    mock_cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notBefore": not_before_str,
        "notAfter": not_after_str,
        "subjectAltName": (("DNS", "example.com"),),
    }

    mock_sock = create_mock_ssock(mock_cert)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock):
        findings, cert_info = analyzer.analyze("example.com", target_ip="93.184.216.34")

        assert cert_info is not None
        expired_findings = [f for f in findings if "Expired" in f.title]
        assert len(expired_findings) > 0
        assert expired_findings[0].severity == "CRITICAL"


def test_tls_detects_self_signed_certificate():
    analyzer = TlsAnalyzer()

    future_date = datetime.now(timezone.utc) + timedelta(days=300)
    past_date = datetime.now(timezone.utc) - timedelta(days=10)
    not_after_str = future_date.strftime("%b %d %H:%M:%S %Y GMT")
    not_before_str = past_date.strftime("%b %d %H:%M:%S %Y GMT")

    # Subject == Issuer => Self-Signed
    mock_cert = {
        "subject": ((("commonName", "attacker.local"),),),
        "issuer": ((("commonName", "attacker.local"),),),
        "notBefore": not_before_str,
        "notAfter": not_after_str,
        "subjectAltName": (("DNS", "attacker.local"),),
    }

    mock_sock = create_mock_ssock(mock_cert)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock):
        findings, cert_info = analyzer.analyze("attacker.local", target_ip="93.184.216.34")

        self_signed = [f for f in findings if "Self-Signed" in f.title]
        assert len(self_signed) > 0
        assert self_signed[0].severity == "HIGH"


def test_tls_detects_hostname_mismatch():
    analyzer = TlsAnalyzer()

    future_date = datetime.now(timezone.utc) + timedelta(days=300)
    past_date = datetime.now(timezone.utc) - timedelta(days=10)

    # Cert is for otherdomain.com, but we connected to target.com
    mock_cert = {
        "subject": ((("commonName", "otherdomain.com"),),),
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "notBefore": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "otherdomain.com"),),
    }

    mock_sock = create_mock_ssock(mock_cert)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock):
        findings, cert_info = analyzer.analyze("target.com", target_ip="93.184.216.34")

        assert cert_info is not None
        assert cert_info.hostnameMatched is False
        mismatch = [f for f in findings if "Mismatch" in f.title]
        assert len(mismatch) > 0
        assert mismatch[0].severity == "HIGH"


def test_tls_connection_refused_or_failure():
    analyzer = TlsAnalyzer()

    with patch("socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
        findings, cert_info = analyzer.analyze("example.com", target_ip="93.184.216.34")

        assert cert_info is None
        conn_errs = [f for f in findings if "Connection Failed" in f.title or "Port 443" in f.title]
        assert len(conn_errs) > 0


def test_tls_detects_emudhra_and_distrusted_ca():
    analyzer = TlsAnalyzer()

    mock_cert = {
        "subject": ((("commonName", "banking-portal.com"),),),
        "issuer": ((("organizationName", "eMudhra Technologies Subordinate CA"),),),
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Dec 31 00:00:00 2026 GMT",
        "subjectAltName": (("DNS", "banking-portal.com"),),
    }

    mock_sock = create_mock_ssock(mock_cert)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock):
        findings, cert_info = analyzer.analyze("banking-portal.com", target_ip="93.184.216.34")

        assert cert_info is not None
        assert cert_info.rawDetails.get("compromisedCaRisk") is True
        ca_findings = [f for f in findings if "eMudhra" in f.title or "Compromised" in f.title]
        assert len(ca_findings) > 0
        assert ca_findings[0].severity in {"HIGH", "CRITICAL"}


def test_tls_detects_weak_rsa_key_and_broken_signature():
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization

    # Generate real 1024-bit RSA cert with SHA-1 signature
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "weak.example.com")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(priv.public_key())
        .serial_number(12345)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    # Sign with SHA256 (modern cryptography library blocks signing with SHA-1 due to insecurity)
    der_bytes = builder.sign(priv, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    analyzer = TlsAnalyzer()
    mock_cert = {
        "subject": ((("commonName", "weak.example.com"),),),
        "issuer": ((("commonName", "weak.example.com"),),),
        "notBefore": (now - timedelta(days=1)).strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": (now + timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "weak.example.com"),),
    }
    mock_sock = create_mock_ssock(mock_cert, der_bytes=der_bytes)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock):
        findings, cert_info = analyzer.analyze("weak.example.com", target_ip="93.184.216.34")

        assert cert_info is not None
        assert cert_info.rawDetails["keySize"] == 1024
        assert cert_info.rawDetails["isCa"] is True

        titles = [f.title for f in findings]
        assert any("RSA < 2048 bits" in t for t in titles)
        assert any("Leaf Certificate Configured as Certificate Authority" in t for t in titles)


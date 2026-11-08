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


def generate_test_cert_der(
    cn="test.example.com",
    issuer_cn="Trusted Public CA",
    not_before=None,
    not_after=None,
    key_size=2048,
    is_ca=False,
    include_sct=False,
):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization

    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subj = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    iss = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer_cn)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(iss)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if include_sct:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"),
                b"\x04\x08test_sct"
            ),
            critical=False
        )
    return builder.sign(priv, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def test_tls_validity_schedule_before_march_2026_allows_398_days():
    """Certificates issued before 15 March 2026 are permitted up to 398 days."""
    analyzer = TlsAnalyzer()

    # Issued Jan 10, 2026 with 395 days validity
    issued = datetime(2026, 1, 10, 0, 0, 0, tzinfo=timezone.utc)
    expires = issued + timedelta(days=395)
    der_bytes = generate_test_cert_der(not_before=issued, not_after=expires)

    mock_cert = {
        "subject": ((("commonName", "test.example.com"),),),
        "issuer": ((("organizationName", "DigiCert Public CA"),),),
        "notBefore": issued.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": expires.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "test.example.com"),),
    }
    mock_sock = create_mock_ssock(mock_cert, der_bytes=der_bytes)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock):
        findings, cert_info = analyzer.analyze("test.example.com", target_ip="93.184.216.34")

        assert cert_info is not None
        validity_issues = [f for f in findings if "Non-Compliant Certificate Validity Duration" in f.title]
        assert len(validity_issues) == 0


def test_tls_validity_schedule_after_march_2026_reduces_limit_to_200_days():
    """Certificates issued on or after 15 March 2026 exceeding 200 days are flagged."""
    analyzer = TlsAnalyzer()

    # Issued April 1, 2026 with 250 days validity (exceeds 200 day SC-081v3 limit)
    issued = datetime(2026, 4, 1, 0, 0, 0, tzinfo=timezone.utc)
    expires = issued + timedelta(days=250)
    der_bytes = generate_test_cert_der(not_before=issued, not_after=expires)

    mock_cert = {
        "subject": ((("commonName", "future.example.com"),),),
        "issuer": ((("organizationName", "Sectigo Public CA"),),),
        "notBefore": issued.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": expires.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "future.example.com"),),
    }
    mock_sock = create_mock_ssock(mock_cert, der_bytes=der_bytes)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock):
        findings, cert_info = analyzer.analyze("future.example.com", target_ip="93.184.216.34")

        assert cert_info is not None
        validity_issues = [f for f in findings if "Non-Compliant Certificate Validity Duration" in f.title]
        assert len(validity_issues) == 1
        finding = validity_issues[0]
        assert finding.severity == "MEDIUM"
        assert finding.evidence["maxAllowedDays"] == 200
        assert finding.evidence["calculatedLifetimeDays"] == 250
        assert "SC-081v3" in finding.evidence["policyReference"]


def test_tls_validity_schedule_transition_boundaries():
    """Exact transition dates: 14 March 2026 gets 398 days, 15 March 2026 gets 200 days."""
    analyzer = TlsAnalyzer()

    # Boundary 1: 14 March 2026 with 250 days -> compliant (limit is 398)
    day_before = datetime(2026, 3, 14, 23, 59, 59, tzinfo=timezone.utc)
    expires1 = day_before + timedelta(days=250)
    der_bytes1 = generate_test_cert_der(not_before=day_before, not_after=expires1)

    mock_cert1 = {
        "subject": ((("commonName", "boundary.example.com"),),),
        "issuer": ((("organizationName", "DigiCert Public CA"),),),
        "notBefore": day_before.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": expires1.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "boundary.example.com"),),
    }
    mock_sock1 = create_mock_ssock(mock_cert1, der_bytes=der_bytes1)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock1):
        findings1, _ = analyzer.analyze("boundary.example.com", target_ip="93.184.216.34")
        assert not any("Non-Compliant Certificate Validity Duration" in f.title for f in findings1)

    # Boundary 2: 15 March 2026 with 250 days -> non-compliant (limit is 200)
    day_of = datetime(2026, 3, 15, 0, 0, 0, tzinfo=timezone.utc)
    expires2 = day_of + timedelta(days=250)
    der_bytes2 = generate_test_cert_der(not_before=day_of, not_after=expires2)

    mock_cert2 = {
        "subject": ((("commonName", "boundary.example.com"),),),
        "issuer": ((("organizationName", "DigiCert Public CA"),),),
        "notBefore": day_of.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": expires2.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "boundary.example.com"),),
    }
    mock_sock2 = create_mock_ssock(mock_cert2, der_bytes=der_bytes2)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock2):
        findings2, _ = analyzer.analyze("boundary.example.com", target_ip="93.184.216.34")
        flagged = [f for f in findings2 if "Non-Compliant Certificate Validity Duration" in f.title]
        assert len(flagged) == 1
        assert flagged[0].evidence["maxAllowedDays"] == 200


def test_tls_validity_schedule_2027_and_2029_transition_boundaries():
    """Deterministic timestamp boundary testing for 2027 (100 days) and 2029 (47 days) schedules."""
    analyzer = TlsAnalyzer()

    # 1. 14 March 2027 23:59:59 UTC -> Limit is 200 days
    # A cert issued on March 14, 2027 with 150 days validity is compliant (150 <= 200)
    day_before_2027 = datetime(2027, 3, 14, 23, 59, 59, tzinfo=timezone.utc)
    expires_2027_ok = day_before_2027 + timedelta(days=150)
    der_2027_ok = generate_test_cert_der(not_before=day_before_2027, not_after=expires_2027_ok)
    mock_cert_2027_ok = {
        "subject": ((("commonName", "b2027.example.com"),),),
        "issuer": ((("organizationName", "DigiCert Public CA"),),),
        "notBefore": day_before_2027.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": expires_2027_ok.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "b2027.example.com"),),
    }
    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=create_mock_ssock(mock_cert_2027_ok, der_bytes=der_2027_ok)):
        findings, _ = analyzer.analyze("b2027.example.com", target_ip="93.184.216.34")
        assert not any("Non-Compliant Certificate Validity Duration" in f.title for f in findings)

    # 2. 15 March 2027 00:00:00 UTC -> Limit is 100 days
    # A cert issued on March 15, 2027 with 150 days validity is non-compliant (150 > 100)
    day_of_2027 = datetime(2027, 3, 15, 0, 0, 0, tzinfo=timezone.utc)
    expires_2027_bad = day_of_2027 + timedelta(days=150)
    der_2027_bad = generate_test_cert_der(not_before=day_of_2027, not_after=expires_2027_bad)
    mock_cert_2027_bad = {
        "subject": ((("commonName", "b2027.example.com"),),),
        "issuer": ((("organizationName", "DigiCert Public CA"),),),
        "notBefore": day_of_2027.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": expires_2027_bad.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "b2027.example.com"),),
    }
    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=create_mock_ssock(mock_cert_2027_bad, der_bytes=der_2027_bad)):
        findings, _ = analyzer.analyze("b2027.example.com", target_ip="93.184.216.34")
        flagged = [f for f in findings if "Non-Compliant Certificate Validity Duration" in f.title]
        assert len(flagged) == 1
        assert flagged[0].evidence["maxAllowedDays"] == 100
        assert flagged[0].evidence["calculatedLifetimeDays"] == 150

    # 3. 14 March 2029 23:59:59 UTC -> Limit is 100 days
    # A cert issued on March 14, 2029 with 60 days validity is compliant (60 <= 100)
    day_before_2029 = datetime(2029, 3, 14, 23, 59, 59, tzinfo=timezone.utc)
    expires_2029_ok = day_before_2029 + timedelta(days=60)
    der_2029_ok = generate_test_cert_der(not_before=day_before_2029, not_after=expires_2029_ok)
    mock_cert_2029_ok = {
        "subject": ((("commonName", "b2029.example.com"),),),
        "issuer": ((("organizationName", "DigiCert Public CA"),),),
        "notBefore": day_before_2029.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": expires_2029_ok.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "b2029.example.com"),),
    }
    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=create_mock_ssock(mock_cert_2029_ok, der_bytes=der_2029_ok)):
        findings, _ = analyzer.analyze("b2029.example.com", target_ip="93.184.216.34")
        assert not any("Non-Compliant Certificate Validity Duration" in f.title for f in findings)

    # 4. 15 March 2029 00:00:00 UTC -> Limit is 47 days
    # A cert issued on March 15, 2029 with 60 days validity is non-compliant (60 > 47)
    day_of_2029 = datetime(2029, 3, 15, 0, 0, 0, tzinfo=timezone.utc)
    expires_2029_bad = day_of_2029 + timedelta(days=60)
    der_2029_bad = generate_test_cert_der(not_before=day_of_2029, not_after=expires_2029_bad)
    mock_cert_2029_bad = {
        "subject": ((("commonName", "b2029.example.com"),),),
        "issuer": ((("organizationName", "DigiCert Public CA"),),),
        "notBefore": day_of_2029.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": expires_2029_bad.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "b2029.example.com"),),
    }
    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=create_mock_ssock(mock_cert_2029_bad, der_bytes=der_2029_bad)):
        findings, _ = analyzer.analyze("b2029.example.com", target_ip="93.184.216.34")
        flagged = [f for f in findings if "Non-Compliant Certificate Validity Duration" in f.title]
        assert len(flagged) == 1
        assert flagged[0].evidence["maxAllowedDays"] == 47
        assert flagged[0].evidence["calculatedLifetimeDays"] == 60


def test_tls_ca_and_self_signed_validity_scope_exemptions():
    """CA certificates and self-signed certificates are exempt from subscriber SC-081v3 limits."""
    analyzer = TlsAnalyzer()

    # 1. Certificate Authority certificate with 10-year (3650 days) lifetime: MUST NOT be flagged for subscriber limit
    now = datetime(2026, 4, 1, 0, 0, 0, tzinfo=timezone.utc)
    expires_ca = now + timedelta(days=3650)
    der_ca = generate_test_cert_der(
        cn="Intermediate CA Authority",
        issuer_cn="Root CA Authority",
        not_before=now,
        not_after=expires_ca,
        is_ca=True
    )
    mock_cert_ca = {
        "subject": ((("commonName", "Intermediate CA Authority"),),),
        "issuer": ((("commonName", "Root CA Authority"),),),
        "notBefore": now.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": expires_ca.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (),
    }
    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=create_mock_ssock(mock_cert_ca, der_bytes=der_ca)):
        findings, _ = analyzer.analyze("ca.internal", target_ip="93.184.216.34")
        assert not any("Non-Compliant Certificate Validity Duration" in f.title for f in findings)

    # 2. Self-signed certificate (issuer == subject) with 500 days lifetime: MUST NOT be flagged for subscriber limit
    expires_self = now + timedelta(days=500)
    der_self = generate_test_cert_der(
        cn="self-signed.local",
        issuer_cn="self-signed.local",
        not_before=now,
        not_after=expires_self,
        is_ca=False
    )
    mock_cert_self = {
        "subject": ((("commonName", "self-signed.local"),),),
        "issuer": ((("commonName", "self-signed.local"),),),
        "notBefore": now.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": expires_self.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "self-signed.local"),),
    }
    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=create_mock_ssock(mock_cert_self, der_bytes=der_self)):
        findings, _ = analyzer.analyze("self-signed.local", target_ip="93.184.216.34")
        assert not any("Non-Compliant Certificate Validity Duration" in f.title for f in findings)
        # However, self-signed finding MUST still be correctly generated
        assert any("Self-Signed TLS Certificate" in f.title or "Self-Signed SSL/TLS Certificate" in f.title for f in findings)


def test_tls_missing_sct_qualification():
    """Missing embedded SCTs are reported with appropriate qualification, not false compromise claims."""
    analyzer = TlsAnalyzer()

    now = datetime.now(timezone.utc)
    # Valid 90-day certificate without embedded SCT extension
    der_bytes = generate_test_cert_der(
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        include_sct=False
    )

    mock_cert = {
        "subject": ((("commonName", "test.example.com"),),),
        "issuer": ((("organizationName", "Let's Encrypt Authority"),),),
        "notBefore": (now - timedelta(days=1)).strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": (now + timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "test.example.com"),),
    }
    mock_sock = create_mock_ssock(mock_cert, der_bytes=der_bytes)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock):
        findings, cert_info = analyzer.analyze("test.example.com", target_ip="93.184.216.34")

        assert cert_info is not None
        sct_findings = [f for f in findings if "Certificate Transparency" in f.title]
        assert len(sct_findings) == 1
        assert sct_findings[0].severity == "LOW"
        assert "No Embedded Certificate Transparency" in sct_findings[0].title
        assert "alternateDeliveryMethods" in sct_findings[0].evidence


def test_tls_ca_name_spoofing_distinction():
    """Self-signed certificate mimicking a distrusted CA is distinguished from authentic CA signature."""
    analyzer = TlsAnalyzer()

    now = datetime.now(timezone.utc)
    # Self-signed certificate with issuer CN matching eMudhra
    mock_cert = {
        "subject": ((("commonName", "eMudhra Technologies Subordinate CA"),),),
        "issuer": ((("commonName", "eMudhra Technologies Subordinate CA"),),),
        "notBefore": (now - timedelta(days=1)).strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": (now + timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "spoof.local"),),
    }
    mock_sock = create_mock_ssock(mock_cert)

    with patch("socket.create_connection"), \
         patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock):
        findings, cert_info = analyzer.analyze("spoof.local", target_ip="93.184.216.34")

        assert cert_info is not None
        spoof_findings = [f for f in findings if "Self-Signed Certificate Claiming Distrusted CA Name" in f.title]
        assert len(spoof_findings) == 1
        assert spoof_findings[0].evidence["isSelfSigned"] is True
        assert spoof_findings[0].evidence["verifiedChain"] is False


import pytest
from app.safety.ssrf_guard import validate_url_safety, SSRFSecurityException


def test_blocks_localhost_and_loopback():
    with pytest.raises(SSRFSecurityException):
        validate_url_safety("http://localhost/admin")

    with pytest.raises(SSRFSecurityException):
        validate_url_safety("http://127.0.0.1:8080")


def test_blocks_cloud_metadata():
    with pytest.raises(SSRFSecurityException):
        validate_url_safety("http://169.254.169.254/latest/meta-data")


def test_blocks_private_networks():
    with pytest.raises(SSRFSecurityException):
        validate_url_safety("http://192.168.1.1/router")

    with pytest.raises(SSRFSecurityException):
        validate_url_safety("http://10.0.0.5:80")


def test_blocks_forbidden_protocols():
    with pytest.raises(SSRFSecurityException):
        validate_url_safety("file:///etc/passwd")

    with pytest.raises(SSRFSecurityException):
        validate_url_safety("gopher://127.0.0.1:70")


def test_allows_valid_public_domain():
    host, ips = validate_url_safety("https://example.com")
    assert host == "example.com"

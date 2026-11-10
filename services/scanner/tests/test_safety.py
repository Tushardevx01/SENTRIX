import pytest
from app.safety.ssrf_guard import (
    validate_url_safety,
    is_ip_forbidden,
    resolve_and_validate_hostname,
    SSRFSecurityException,
)


def test_blocks_localhost_and_loopback():
    vectors = [
        "http://localhost/admin",
        "http://127.0.0.1:8080",
        "http://127.0.0.2",
        "http://127.1",
        "http://0.0.0.0",
        "http://[::1]",
        "http://[0:0:0:0:0:0:0:1]",
    ]
    for vec in vectors:
        with pytest.raises(SSRFSecurityException):
            validate_url_safety(vec)


def test_blocks_cloud_metadata():
    vectors = [
        "http://169.254.169.254/latest/meta-data",
        "http://169.254.169.254/computeMetadata/v1",
        "http://metadata.google.internal",
    ]
    for vec in vectors:
        with pytest.raises(SSRFSecurityException):
            validate_url_safety(vec)


def test_blocks_private_networks_rfcs():
    vectors = [
        "http://10.0.0.1/admin",
        "http://10.255.255.254",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://192.168.0.1",
        "http://192.168.1.254",
        "http://100.64.0.1",     # Carrier-grade NAT
        "http://192.0.2.1",      # TEST-NET-1
        "http://198.51.100.1",   # TEST-NET-2
        "http://203.0.113.1",    # TEST-NET-3
    ]
    for vec in vectors:
        with pytest.raises(SSRFSecurityException):
            validate_url_safety(vec)


def test_blocks_ipv6_reserved_and_mapped():
    vectors = [
        "http://[fe80::1]",             # Link-local
        "http://[fc00::1]",             # Unique local
        "http://[fd12:3456:789a::1]",   # Unique local
        "http://[::ffff:127.0.0.1]",    # IPv4-mapped IPv6 loopback
        "http://[::ffff:169.254.169.254]",  # IPv4-mapped IPv6 cloud metadata
        "http://[::ffff:10.0.0.1]",     # IPv4-mapped IPv6 private
        "http://[::ffff:192.168.1.1]",
    ]
    for vec in vectors:
        with pytest.raises(SSRFSecurityException):
            validate_url_safety(vec)


def test_nat64_checks_embedded_ipv4_destination():
    forbidden, reason = is_ip_forbidden("64:ff9b::fcf:b7ae")
    assert forbidden is False
    assert reason == ""

    for address in ("64:ff9b::a00:1", "64:ff9b::c000:201", "64:ff9b::a9fe:a9fe"):
        forbidden, reason = is_ip_forbidden(address)
        assert forbidden is True
        assert "restricted destination" in reason


def test_blocks_embedded_credentials():
    vectors = [
        "https://admin:secret@example.com/path",
        "http://user@example.com",
    ]
    for vec in vectors:
        with pytest.raises(SSRFSecurityException) as exc_info:
            validate_url_safety(vec)
        assert "credentials" in str(exc_info.value).lower()


def test_blocks_forbidden_protocols():
    vectors = [
        "file:///etc/passwd",
        "gopher://127.0.0.1:70",
        "ftp://example.com/file",
        "ssh://example.com",
        "dict://example.com",
    ]
    for vec in vectors:
        with pytest.raises(SSRFSecurityException):
            validate_url_safety(vec)


def test_blocks_forbidden_ports():
    vectors = [
        "http://example.com:22",
        "http://example.com:25",
        "http://example.com:3306",
        "http://example.com:6379",
        "http://example.com:27017",
    ]
    for vec in vectors:
        with pytest.raises(SSRFSecurityException) as exc_info:
            validate_url_safety(vec)
        assert "Port" in str(exc_info.value)


def test_dns_resolution_failure_fails_closed():
    with pytest.raises(SSRFSecurityException) as exc_info:
        resolve_and_validate_hostname("this-subdomain-definitely-does-not-exist-sentrix-test-999.invalid", 443)
    assert "Unable to resolve" in str(exc_info.value) or "DNS" in str(exc_info.value)


def test_allows_valid_public_domain():
    from unittest.mock import patch
    import socket
    # Mock DNS resolution so test runs reliably in offline sandbox environments
    mock_addrinfo = [
        (socket.AF_INET, socket.SocketKind.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        host, ips = validate_url_safety("https://example.com")
        assert host == "example.com"
        assert len(ips) > 0
        for ip in ips:
            forbidden, reason = is_ip_forbidden(ip)
            assert forbidden is False

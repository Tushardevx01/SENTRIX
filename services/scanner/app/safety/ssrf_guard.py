import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, List, Optional


class SSRFSecurityException(Exception):
    """Raised when a URL attempts to target internal or forbidden network ranges."""
    pass


FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # AWS / GCP / Azure metadata service
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    ipaddress.ip_network("::1/128"),             # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 Unique Local Address
    ipaddress.ip_network("fe80::/10"),           # IPv6 Link-Local
]

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}


def validate_url_safety(raw_url: str) -> Tuple[str, List[str]]:
    """
    Validates that a URL does not target localhost, private addresses,
    cloud metadata endpoints, or unsupported protocols.
    Returns (canonical_hostname, resolved_ips).
    """
    if not raw_url or not isinstance(raw_url, str):
        raise SSRFSecurityException("Empty or invalid URL provided.")

    parsed = urlparse(raw_url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFSecurityException(f"Unsupported scheme '{scheme}'. Only http and https are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFSecurityException("No valid hostname found in URL.")

    # Check for direct loopback keywords
    if hostname.lower() in {"localhost", "metadata.google.internal", "instance-data"}:
        raise SSRFSecurityException(f"Targeting '{hostname}' is strictly prohibited.")

    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFSecurityException(f"Port {port} is not in the allowed scan port list ({ALLOWED_PORTS}).")

    # Resolve IP addresses
    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        for entry in addr_info:
            ip_str = entry[4][0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
    except socket.gaierror as e:
        # Domain cannot be resolved, but isn't necessarily SSRF.
        return hostname, []

    # Check each resolved IP against forbidden subnets
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                raise SSRFSecurityException(f"Resolved IP {ip_str} belongs to a restricted/private network.")

            for net in FORBIDDEN_NETWORKS:
                if ip_obj in net:
                    raise SSRFSecurityException(f"Resolved IP {ip_str} belongs to restricted network {net}.")
        except ValueError:
            raise SSRFSecurityException(f"Invalid IP address format encountered: {ip_str}")

    return hostname, resolved_ips

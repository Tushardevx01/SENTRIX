import ipaddress
import socket
from urllib.parse import urlsplit, urljoin
from typing import Tuple, List, Dict, Optional, Set
import anyio
import httpcore
from httpcore._backends.anyio import AnyIOBackend


class SSRFSecurityException(Exception):
    """Raised when a URL attempts to target internal, private, loopback, or forbidden network ranges."""
    pass


FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),           # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier Grade NAT
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),       # Link-Local / Cloud Metadata (AWS/GCP/Azure)
    ipaddress.ip_network("172.16.0.0/12"),        # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),         # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),         # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),       # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),        # Benchmark testing
    ipaddress.ip_network("198.51.100.0/24"),      # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),       # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("255.255.255.255/32"),   # Limited Broadcast
    ipaddress.ip_network("::/128"),               # Unspecified
    ipaddress.ip_network("::1/128"),              # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),             # IPv6 Unique Local Address
    ipaddress.ip_network("fe80::/10"),            # IPv6 Link-Local
    ipaddress.ip_network("ff00::/8"),             # IPv6 Multicast
    ipaddress.ip_network("2001:db8::/32"),        # Documentation
]
NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}

FORBIDDEN_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
    "169.254.169.254",
}


def is_ip_forbidden(ip_str: str) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address (IPv4 or IPv6, including IPv4-mapped IPv6)
    belongs to a restricted, loopback, private, or metadata range.
    Returns (is_forbidden, reason).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Malformed IP address representation: {ip_str}"

    if isinstance(ip_obj, ipaddress.IPv6Address):
        # DNS64 may synthesize public IPv4 destinations under this prefix.
        # Apply the IPv4 policy to the embedded address instead of rejecting
        # the translation prefix as reserved.
        if ip_obj in NAT64_WELL_KNOWN_PREFIX:
            embedded_ipv4 = ipaddress.IPv4Address(ip_obj.packed[-4:])
            forbidden, reason = is_ip_forbidden(str(embedded_ipv4))
            if forbidden:
                return True, f"NAT64 address {ip_str} embeds a restricted destination: {reason}"
            return False, ""

        # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
        if ip_obj.ipv4_mapped:
            return is_ip_forbidden(str(ip_obj.ipv4_mapped))

    # Standard ipaddress attribute classifications
    if ip_obj.is_loopback:
        return True, f"Loopback address ({ip_str}) is strictly prohibited."
    if ip_obj.is_private:
        return True, f"Private network address ({ip_str}) is prohibited."
    if ip_obj.is_link_local:
        return True, f"Link-local address ({ip_str}) is prohibited."
    if ip_obj.is_multicast:
        return True, f"Multicast address ({ip_str}) is prohibited."
    if ip_obj.is_reserved:
        return True, f"Reserved address ({ip_str}) is prohibited."
    if ip_obj.is_unspecified:
        return True, f"Unspecified address ({ip_str}) is prohibited."

    # Explicit subnet checks
    for network in FORBIDDEN_NETWORKS:
        try:
            if ip_obj in network:
                return True, f"IP {ip_str} belongs to restricted network {network}."
        except TypeError:
            # Different address family
            continue

    return False, ""


def validate_url_syntax_and_authority(raw_url: str) -> Tuple[str, str, int]:
    """
    Validates URL scheme, authority, port, and rejects embedded credentials or invalid characters.
    Returns (scheme, hostname, port).
    """
    if not raw_url or not isinstance(raw_url, str):
        raise SSRFSecurityException("Empty or invalid URL provided.")

    target = raw_url.strip()
    parsed = urlsplit(target)

    # 1. Scheme validation
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFSecurityException(f"Unsupported scheme '{scheme}'. Only http and https are allowed.")

    # 2. Reject embedded user credentials
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        raise SSRFSecurityException("URLs containing embedded username/password credentials are strictly prohibited.")

    # 3. Hostname validation
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise SSRFSecurityException("No valid hostname found in target URL.")

    # Check forbidden hostnames
    if hostname in FORBIDDEN_HOSTNAMES:
        raise SSRFSecurityException(f"Targeting host '{hostname}' is strictly prohibited by security perimeter policy.")

    # Check for direct decimal or octal obfuscation of loopback
    if hostname.isdigit():
        raise SSRFSecurityException("Integer representation of IP address in hostname is prohibited.")

    # 4. Port validation
    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFSecurityException(f"Port {port} is not in the allowed scan port list ({ALLOWED_PORTS}).")

    return scheme, hostname, port


def resolve_and_validate_hostname(hostname: str, port: int) -> List[str]:
    """
    Performs comprehensive DNS resolution across A (IPv4) and AAAA (IPv6) records.
    Validates all resolved addresses against SSRF policies.
    Fails closed if DNS resolution fails or any resolved IP is forbidden.
    """
    # If hostname is a direct literal IP
    try:
        ipaddress.ip_address(hostname)
        forbidden, reason = is_ip_forbidden(hostname)
        if forbidden:
            raise SSRFSecurityException(reason)
        return [hostname]
    except ValueError:
        pass

    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        for entry in addr_info:
            ip_str = entry[4][0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
    except socket.gaierror as e:
        raise SSRFSecurityException(f"DNS resolution failed for destination '{hostname}': {e.strerror or str(e)}")
    except Exception as e:
        raise SSRFSecurityException(f"DNS resolution encountered an unexpected error for '{hostname}': {str(e)}")

    if not resolved_ips:
        raise SSRFSecurityException(f"DNS resolution returned zero address records for '{hostname}'.")

    # Evaluate EVERY resolved IP address. If ANY address is forbidden, reject the entire destination.
    for ip_str in resolved_ips:
        forbidden, reason = is_ip_forbidden(ip_str)
        if forbidden:
            raise SSRFSecurityException(f"Resolved destination IP {ip_str} for host '{hostname}' is restricted: {reason}")

    return resolved_ips


def validate_url_safety(raw_url: str) -> Tuple[str, List[str]]:
    """
    Complete pre-flight SSRF and authority safety validation.
    Returns (canonical_hostname, resolved_ips).
    """
    scheme, hostname, port = validate_url_syntax_and_authority(raw_url)
    resolved_ips = resolve_and_validate_hostname(hostname, port)
    return hostname, resolved_ips


class PinnedIPNetworkBackend(AnyIOBackend):
    """
    Custom httpcore network backend that enforces connection-time IP pinning.
    Ensures TCP connects exclusively to pre-validated public IPs, preventing
    Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks while preserving
    TLS SNI and hostname certificate validation.
    """

    def __init__(self, ip_map: Optional[Dict[str, str]] = None):
        super().__init__()
        self.ip_map = ip_map or {}

    def pin_host(self, host: str, ip: str) -> None:
        self.ip_map[host.lower()] = ip

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options=None,
    ):
        host_key = host.lower()
        target_ip = self.ip_map.get(host_key, host)

        # Validate that target_ip is safe before connecting
        forbidden, reason = is_ip_forbidden(target_ip)
        if forbidden:
            raise SSRFSecurityException(f"Connection-time SSRF check failed: {reason}")

        return await super().connect_tcp(
            target_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

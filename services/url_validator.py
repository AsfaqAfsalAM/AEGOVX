"""
services/url_validator.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Validates and normalizes target URLs, detects internal/reserved targets,
and enforces strict Server-Side Request Forgery (SSRF) defense.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

MAX_URL_LENGTH = 2048

# Blocked IP networks (Loopback, RFC1918, Link-local, Multicast, Reserved, etc.)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # IPv4 loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 private
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("0.0.0.0/8"),        # "this" network
    ipaddress.ip_network("100.64.0.0/10"),    # shared address (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("255.255.255.255/32"), # broadcast
    # IPv6 ranges
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("::/128"),           # unspecified
    ipaddress.ip_network("fc00::/7"),         # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),         # IPv6 multicast
    ipaddress.ip_network("2001:db8::/32"),    # documentation
]

_BLOCKED_SUFFIXES = (
    ".local",
    ".internal",
    ".localhost",
    ".onion",
    ".lan",
    ".corp",
    ".home",
    ".arpa",
    ".intranet",
    ".priv",
    ".test",
    ".example",
    ".invalid",
)

_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}


@dataclass
class NormalizedURL:
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: int
    path: str
    query: str
    is_ip: bool
    ip_type: str | None
    resolved_ips: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_ip_address(val: str) -> tuple[bool, str | None]:
    """Check if the string is an IPv4 or IPv6 address."""
    clean = val.strip("[]")
    try:
        addr = ipaddress.ip_address(clean)
        return True, "ipv4" if addr.version == 4 else "ipv6"
    except ValueError:
        return False, None


def is_private_or_blocked_ip(ip_str: str) -> bool:
    """Return True if ip_str falls inside any blocked or private network."""
    clean = ip_str.strip("[]")
    try:
        addr = ipaddress.ip_address(clean)
    except ValueError:
        return True  # If unparseable, block safely
    return any(addr in net for net in _BLOCKED_NETWORKS)


def resolve_and_verify_hostname(hostname: str) -> list[str]:
    """
    Resolve *hostname* to IP addresses and verify none are in blocked/private ranges.
    Raises ValueError on resolution error or SSRF match.
    """
    clean_host = hostname.strip("[]").lower()

    if clean_host in _BLOCKED_HOSTNAMES:
        raise ValueError(f"Blocked internal hostname or loopback address: '{hostname}'.")

    if any(clean_host.endswith(sfx) for sfx in _BLOCKED_SUFFIXES):
        raise ValueError(f"Requests to internal/private domain zones ({clean_host}) are not permitted.")

    # Check direct IP
    is_ip, _ = is_ip_address(clean_host)
    if is_ip:
        if is_private_or_blocked_ip(clean_host):
            raise ValueError(f"Direct connection to private/internal IP address '{clean_host}' is blocked (SSRF defense).")
        return [clean_host]

    # DNS resolution
    try:
        infos = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve domain name '{hostname}': {exc.strerror or exc}") from exc

    resolved: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in resolved:
            resolved.append(ip)

    if not resolved:
        raise ValueError(f"Domain '{hostname}' did not resolve to any IP address.")

    for ip in resolved:
        if is_private_or_blocked_ip(ip):
            raise ValueError(
                f"Domain '{hostname}' resolves to protected internal IP address {ip}. Request blocked for SSRF security."
            )

    return resolved


def validate_and_normalize_url(raw_url: str) -> NormalizedURL:
    """
    Validate, sanitize, normalize, and verify safety of a user-submitted URL.
    Returns a NormalizedURL dataclass.
    """
    if not raw_url or not raw_url.strip():
        raise ValueError("URL cannot be empty. Please enter a valid website address.")

    cleaned = raw_url.strip()

    if len(cleaned) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.")

    # Check if a URI scheme is specified before colon
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*):", cleaned)
    if scheme_match:
        raw_scheme = scheme_match.group(1).lower()
        if raw_scheme not in ("http", "https"):
            raise ValueError(f"Unsupported protocol '{raw_scheme}:'. Only HTTP and HTTPS are permitted.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned):
            cleaned = f"{raw_scheme}://" + cleaned[len(raw_scheme) + 1:].lstrip("/")
    else:
        # No scheme prefix provided, default to https
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
    except Exception as exc:
        raise ValueError(f"Invalid URL structure: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported protocol '{scheme}:'. Only HTTP and HTTPS are permitted.")

    if not parsed.netloc:
        raise ValueError("URL is missing a valid hostname.")

    # Handle user:pass if present (strip credential components to avoid abuse)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Could not extract a valid hostname from the submitted URL.")
    hostname = hostname.lower().strip()

    # Reject non-printable / control characters in hostname
    if any(ord(c) < 33 or ord(c) > 126 for c in hostname):
        # Could be IDN / Punycode or Unicode
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except Exception:
            raise ValueError("Hostname contains invalid or unencodeable characters.")

    # Determine port
    if parsed.port:
        port = parsed.port
    else:
        port = 443 if scheme == "https" else 80

    path = parsed.path or "/"
    query = parsed.query or ""

    is_ip, ip_type = is_ip_address(hostname)

    # Perform SSRF DNS resolution and safety check
    resolved_ips = resolve_and_verify_hostname(hostname)

    # Reconstruct normalized URL (strip fragment, lowercase scheme and host)
    netloc = hostname
    if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
        netloc = f"{hostname}:{port}"

    normalized_url = urlunparse((scheme, netloc, path, "", query, ""))

    return NormalizedURL(
        original_url=raw_url,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query=query,
        is_ip=is_ip,
        ip_type=ip_type,
        resolved_ips=resolved_ips,
    )

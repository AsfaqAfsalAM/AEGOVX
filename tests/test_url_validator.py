"""
tests/test_url_validator.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for URL validation, normalization, and SSRF prevention.
"""

import pytest
from services.url_validator import (
    is_ip_address,
    is_private_or_blocked_ip,
    validate_and_normalize_url,
)


class TestIPAddressChecks:
    def test_ipv4_detection(self):
        is_ip, ip_type = is_ip_address("192.168.1.1")
        assert is_ip is True
        assert ip_type == "ipv4"

    def test_ipv6_detection(self):
        is_ip, ip_type = is_ip_address("::1")
        assert is_ip is True
        assert ip_type == "ipv6"

    def test_domain_is_not_ip(self):
        is_ip, ip_type = is_ip_address("example.com")
        assert is_ip is False
        assert ip_type is None

    def test_blocked_private_ranges(self):
        # Loopback
        assert is_private_or_blocked_ip("127.0.0.1") is True
        assert is_private_or_blocked_ip("127.255.255.255") is True
        # RFC 1918
        assert is_private_or_blocked_ip("10.0.0.5") is True
        assert is_private_or_blocked_ip("172.16.50.1") is True
        assert is_private_or_blocked_ip("192.168.0.1") is True
        # AWS metadata / Link-local
        assert is_private_or_blocked_ip("169.254.169.254") is True
        # IPv6 loopback
        assert is_private_or_blocked_ip("::1") is True
        # Public IP should not be blocked
        assert is_private_or_blocked_ip("8.8.8.8") is False
        assert is_private_or_blocked_ip("1.1.1.1") is False


class TestURLValidationAndSSRF:
    def test_empty_url_rejected(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_and_normalize_url("")

    def test_unsupported_scheme_rejected(self):
        with pytest.raises(ValueError, match="Unsupported protocol"):
            validate_and_normalize_url("ftp://example.com/file.txt")

        with pytest.raises(ValueError, match="Unsupported protocol"):
            validate_and_normalize_url("file:///etc/passwd")

        with pytest.raises(ValueError, match="Unsupported protocol"):
            validate_and_normalize_url("javascript:alert(1)")

    def test_localhost_blocked(self):
        with pytest.raises(ValueError, match="Blocked internal hostname"):
            validate_and_normalize_url("http://localhost:8080")

        with pytest.raises(ValueError, match="Blocked internal hostname"):
            validate_and_normalize_url("http://127.0.0.1")

    def test_internal_suffix_blocked(self):
        with pytest.raises(ValueError, match="internal/private domain zones"):
            validate_and_normalize_url("http://server.local")

        with pytest.raises(ValueError, match="internal/private domain zones"):
            validate_and_normalize_url("http://backend.internal")

    def test_private_ip_ssrf_blocked(self):
        with pytest.raises(ValueError, match="Direct connection to private/internal IP"):
            validate_and_normalize_url("http://192.168.1.1")

        with pytest.raises(ValueError, match="Direct connection to private/internal IP"):
            validate_and_normalize_url("http://169.254.169.254/latest/meta-data")

    def test_valid_public_domain_normalized(self):
        norm = validate_and_normalize_url("example.com")
        assert norm.scheme == "https"
        assert norm.hostname == "example.com"
        assert norm.port == 443
        assert norm.path == "/"
        assert norm.is_ip is False
        assert len(norm.resolved_ips) > 0

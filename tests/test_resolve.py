"""Tests for kerbwolf.core.resolve - DNS resolution helpers."""

import socket
from unittest.mock import MagicMock, patch

from kerbwolf.core.resolve import is_ip, resolve_host

# ---------------------------------------------------------------------------
# is_ip
# ---------------------------------------------------------------------------


class TestIsIp:
    def test_ipv4(self):
        assert is_ip("10.0.0.1") is True

    def test_ipv6(self):
        assert is_ip("::1") is True

    def test_ipv6_full(self):
        assert is_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_hostname(self):
        assert is_ip("dc01.evil.corp") is False

    def test_empty_string(self):
        assert is_ip("") is False

    def test_hostname_with_digits(self):
        assert is_ip("host-10.corp.local") is False

    def test_ipv4_mapped_ipv6(self):
        assert is_ip("::ffff:10.0.0.1") is True

    def test_partial_ip(self):
        assert is_ip("10.0.0") is False


# ---------------------------------------------------------------------------
# resolve_srv
# ---------------------------------------------------------------------------


class TestResolveSrv:
    def test_returns_target_on_success(self):
        from kerbwolf.core.resolve import resolve_srv

        mock_answer = MagicMock()
        mock_answer.target = MagicMock(__str__=lambda self: "DC01.evil.corp.")
        with patch("kerbwolf.core.resolve.dns.resolver.resolve", return_value=[mock_answer]):
            result = resolve_srv("_kerberos._tcp.evil.corp")
        assert result == "DC01.evil.corp"

    def test_returns_none_on_exception(self):
        from kerbwolf.core.resolve import resolve_srv

        with patch("kerbwolf.core.resolve.dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
            result = resolve_srv("_kerberos._tcp.nonexistent.local")
        assert result is None

    def test_returns_none_on_empty_answers(self):
        from kerbwolf.core.resolve import resolve_srv

        with patch("kerbwolf.core.resolve.dns.resolver.resolve", return_value=[]):
            result = resolve_srv("_kerberos._tcp.evil.corp")
        assert result is None


# ---------------------------------------------------------------------------
# resolve_host
# ---------------------------------------------------------------------------


class TestResolveHost:
    def test_returns_ip_on_success(self):
        fake_results = [(socket.AF_INET, 1, 6, "", ("10.0.0.1", 0))]
        with patch("kerbwolf.core.resolve.socket.getaddrinfo", return_value=fake_results):
            assert resolve_host("dc01.evil.corp") == "10.0.0.1"

    def test_prefers_ipv4(self):
        fake_results = [
            (socket.AF_INET6, 1, 6, "", ("::1", 0, 0, 0)),
            (socket.AF_INET, 1, 6, "", ("10.0.0.1", 0)),
        ]
        with patch("kerbwolf.core.resolve.socket.getaddrinfo", return_value=fake_results):
            assert resolve_host("dc01.evil.corp") == "10.0.0.1"

    def test_falls_back_to_ipv6(self):
        fake_results = [(socket.AF_INET6, 1, 6, "", ("::1", 0, 0, 0))]
        with patch("kerbwolf.core.resolve.socket.getaddrinfo", return_value=fake_results):
            assert resolve_host("dc01.evil.corp") == "::1"

    def test_returns_none_on_gaierror(self):
        with patch("kerbwolf.core.resolve.socket.getaddrinfo", side_effect=socket.gaierror("not found")):
            assert resolve_host("nonexistent.local") is None

    def test_returns_none_on_empty_results(self):
        with patch("kerbwolf.core.resolve.socket.getaddrinfo", return_value=[]):
            assert resolve_host("dc.corp") is None

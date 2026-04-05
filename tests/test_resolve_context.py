"""Tests for resolve_context() - unified DC resolution from CLI args, ccache, and DNS."""

import argparse
from unittest.mock import patch

import pytest

from kerbwolf.cli._common import resolve_context
from kerbwolf.log import Logger


def _make_args(**overrides):
    """Build a minimal argparse.Namespace for resolve_context()."""
    defaults = {
        "domain": None,
        "user": None,
        "dc_ip": None,
        "dc_hostname": None,
        "kerberos": False,
        "ccache": None,
        "timeout": 10.0,
        "verbose": 0,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _no_env_ccache():
    return None


# ---------------------------------------------------------------------------
# Basic resolution with explicit flags
# ---------------------------------------------------------------------------


class TestResolveContextExplicit:
    """Tests where domain and dc_ip are provided explicitly (no ccache, no DNS)."""

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.resolve_host", return_value=None)
    @patch("kerbwolf.cli._common.is_ip", return_value=True)
    def test_domain_and_dc_ip(self, mock_is_ip, mock_host, mock_srv):
        args = _make_args(domain="evil.corp", dc_ip="10.0.0.1", user="admin")
        ctx = resolve_context(args, Logger())
        assert ctx.domain == "evil.corp"
        assert ctx.realm == "EVIL.CORP"
        assert ctx.dc_ip == "10.0.0.1"
        assert ctx.username == "admin"
        assert ctx.dc_hostname is None

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.resolve_host", return_value=None)
    @patch("kerbwolf.cli._common.is_ip", return_value=True)
    def test_dc_hostname_override(self, mock_is_ip, mock_host, mock_srv):
        args = _make_args(domain="evil.corp", dc_ip="10.0.0.1", dc_hostname="DC01.evil.corp")
        ctx = resolve_context(args, Logger())
        assert ctx.dc_hostname == "DC01.evil.corp"
        assert ctx.dc_ip == "10.0.0.1"

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.resolve_host", return_value=None)
    @patch("kerbwolf.cli._common.is_ip", return_value=True)
    def test_timeout_propagates(self, mock_is_ip, mock_host, mock_srv):
        args = _make_args(domain="evil.corp", dc_ip="10.0.0.1", timeout=30.0)
        ctx = resolve_context(args, Logger())
        assert ctx.timeout == 30.0


class TestResolveContextMissingDomain:
    """Error when domain cannot be determined."""

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    def test_no_domain_exits(self):
        args = _make_args(dc_ip="10.0.0.1")
        with pytest.raises(SystemExit):
            resolve_context(args, Logger())


class TestResolveContextMissingDC:
    """Error when DC IP cannot be resolved."""

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.resolve_host", return_value=None)
    @patch("kerbwolf.cli._common.is_ip", return_value=False)
    def test_unresolvable_dc_exits(self, mock_is_ip, mock_host, mock_srv):
        args = _make_args(domain="evil.corp")
        with pytest.raises(SystemExit):
            resolve_context(args, Logger())


# ---------------------------------------------------------------------------
# SRV-first resolution
# ---------------------------------------------------------------------------


class TestResolveContextSRV:
    """SRV lookup provides both hostname and IP."""

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.resolve_srv", return_value="DC01.evil.corp")
    @patch("kerbwolf.cli._common.resolve_host", return_value="10.0.0.1")
    def test_srv_gives_hostname_and_ip(self, mock_host, mock_srv):
        args = _make_args(domain="evil.corp")
        ctx = resolve_context(args, Logger())
        assert ctx.dc_ip == "10.0.0.1"
        assert ctx.dc_hostname == "DC01.evil.corp"
        mock_srv.assert_called_once_with("_kerberos._tcp.evil.corp")

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.resolve_srv", return_value="DC01.evil.corp")
    @patch("kerbwolf.cli._common.is_ip", return_value=True)
    def test_dc_ip_overrides_srv_ip(self, mock_is_ip, mock_srv):
        """--dc-ip overrides the SRV IP but keeps the SRV hostname."""
        with patch("kerbwolf.cli._common.resolve_host", return_value="10.0.0.1"):
            args = _make_args(domain="evil.corp", dc_ip="10.0.0.99")
            ctx = resolve_context(args, Logger())
        assert ctx.dc_ip == "10.0.0.99"
        assert ctx.dc_hostname == "DC01.evil.corp"

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.resolve_srv", return_value="DC01.evil.corp")
    def test_dc_hostname_overrides_srv_hostname(self, mock_srv):
        """--dc-hostname overrides the SRV hostname."""
        with patch("kerbwolf.cli._common.resolve_host", return_value="10.0.0.1"):
            args = _make_args(domain="evil.corp", dc_hostname="DC02.evil.corp")
            ctx = resolve_context(args, Logger())
        assert ctx.dc_hostname == "DC02.evil.corp"


# ---------------------------------------------------------------------------
# --dc-ip as hostname (not IP)
# ---------------------------------------------------------------------------


class TestResolveContextDcIpAsHostname:
    """--dc-ip can be a hostname that gets resolved."""

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.is_ip", return_value=False)
    @patch("kerbwolf.cli._common.resolve_host", return_value="10.0.0.1")
    def test_dc_ip_hostname_resolved(self, mock_host, mock_is_ip, mock_srv):
        args = _make_args(domain="evil.corp", dc_ip="DC01.evil.corp")
        ctx = resolve_context(args, Logger())
        assert ctx.dc_ip == "10.0.0.1"
        assert ctx.dc_hostname == "DC01.evil.corp"

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.is_ip", return_value=False)
    @patch("kerbwolf.cli._common.resolve_host", return_value=None)
    def test_dc_ip_hostname_unresolvable_exits(self, mock_host, mock_is_ip, mock_srv):
        args = _make_args(domain="evil.corp", dc_ip="unreachable.corp")
        with pytest.raises(SystemExit):
            resolve_context(args, Logger())


# ---------------------------------------------------------------------------
# Domain A/AAAA fallback
# ---------------------------------------------------------------------------


class TestResolveContextDomainFallback:
    """When SRV fails and no --dc-ip, try resolving the domain directly."""

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.resolve_host", return_value="10.0.0.1")
    def test_domain_a_record_fallback(self, mock_host, mock_srv):
        args = _make_args(domain="evil.corp")
        ctx = resolve_context(args, Logger())
        assert ctx.dc_ip == "10.0.0.1"
        assert ctx.dc_hostname is None


# ---------------------------------------------------------------------------
# Ccache auto-detection
# ---------------------------------------------------------------------------


class TestResolveContextCcache:
    """When -k -c is set, domain and username come from ccache principal."""

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.get_ccache_info", return_value=("Administrator", "evil.corp"))
    @patch("kerbwolf.cli._common.resolve_srv", return_value="DC01.evil.corp")
    @patch("kerbwolf.cli._common.resolve_host", return_value="10.0.0.1")
    def test_ccache_auto_detect(self, mock_host, mock_srv, mock_ccinfo):
        args = _make_args(kerberos=True, ccache="/tmp/admin.ccache")
        ctx = resolve_context(args, Logger())
        assert ctx.domain == "evil.corp"
        assert ctx.realm == "EVIL.CORP"
        assert ctx.username == "Administrator"

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.get_ccache_info", return_value=("Administrator", "evil.corp"))
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.resolve_host", return_value=None)
    @patch("kerbwolf.cli._common.is_ip", return_value=True)
    def test_explicit_domain_overrides_ccache(self, mock_is_ip, mock_host, mock_srv, mock_ccinfo):
        args = _make_args(kerberos=True, ccache="/tmp/admin.ccache", domain="other.corp", dc_ip="10.0.0.1")
        ctx = resolve_context(args, Logger())
        assert ctx.domain == "other.corp"

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.get_ccache_info", return_value=("Administrator", "evil.corp"))
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.resolve_host", return_value=None)
    @patch("kerbwolf.cli._common.is_ip", return_value=True)
    def test_explicit_user_overrides_ccache(self, mock_is_ip, mock_host, mock_srv, mock_ccinfo):
        args = _make_args(kerberos=True, ccache="/tmp/admin.ccache", domain="evil.corp", user="other_user", dc_ip="10.0.0.1")
        ctx = resolve_context(args, Logger())
        assert ctx.username == "other_user"

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.get_ccache_info", side_effect=Exception("corrupt ccache"))
    def test_ccache_read_failure_exits(self, mock_ccinfo):
        args = _make_args(kerberos=True, ccache="/tmp/bad.ccache")
        with pytest.raises(SystemExit):
            resolve_context(args, Logger())

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    def test_ccache_without_kerberos_warns(self, capsys):
        """Providing -c without -k should warn but continue if -d is given."""
        args = _make_args(domain="evil.corp", ccache="/tmp/admin.ccache")
        with patch("kerbwolf.cli._common.resolve_srv", return_value=None), patch("kerbwolf.cli._common.resolve_host", return_value="10.0.0.1"):
            ctx = resolve_context(args, Logger())
        assert "ccache" in capsys.readouterr().err.lower() or ctx.dc_ip == "10.0.0.1"

    @patch("kerbwolf.cli._common._env_ccache", _no_env_ccache)
    @patch("kerbwolf.cli._common.get_ccache_info", return_value=("admin", "evil.corp"))
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.resolve_host", return_value=None)
    @patch("kerbwolf.cli._common.is_ip", return_value=True)
    def test_ccache_writes_back_to_args(self, mock_is_ip, mock_host, mock_srv, mock_ccinfo):
        """resolve_context() should write domain/user back to args for downstream code."""
        args = _make_args(kerberos=True, ccache="/tmp/admin.ccache", dc_ip="10.0.0.1")
        resolve_context(args, Logger())
        assert args.domain == "evil.corp"
        assert args.user == "admin"


# ---------------------------------------------------------------------------
# KRB5CCNAME env var
# ---------------------------------------------------------------------------


class TestResolveContextEnvCcache:
    @patch("kerbwolf.cli._common._env_ccache", return_value="/tmp/env.ccache")
    @patch("kerbwolf.cli._common.get_ccache_info", return_value=("envuser", "env.corp"))
    @patch("kerbwolf.cli._common.resolve_srv", return_value=None)
    @patch("kerbwolf.cli._common.resolve_host", return_value="10.0.0.2")
    def test_env_ccache_used_with_kerberos(self, mock_host, mock_srv, mock_ccinfo, mock_env):
        args = _make_args(kerberos=True)
        ctx = resolve_context(args, Logger())
        assert ctx.domain == "env.corp"
        assert ctx.username == "envuser"

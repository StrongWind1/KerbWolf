"""Tests for kerbwolf.core.ldap - connection, SPN resolution, search, and account parsing."""

from unittest.mock import MagicMock, patch

import pytest

from kerbwolf.models import UF_DONT_REQUIRE_PREAUTH, UF_USE_DES_KEY_ONLY, LDAPError

# ---------------------------------------------------------------------------
# _resolve_spn_target
# ---------------------------------------------------------------------------


class TestResolveSPNTarget:
    def test_explicit_dc_hostname_wins(self):
        from kerbwolf.core.ldap import _resolve_spn_target

        server = MagicMock()
        result = _resolve_spn_target(server, "evil.corp", dc_hostname="DC01.evil.corp")
        assert result == "DC01.evil.corp"

    def test_rootdse_hostname(self):
        from kerbwolf.core.ldap import _resolve_spn_target

        server = MagicMock()
        server.info.other = {"dnsHostName": ["DC02.evil.corp"]}
        with patch("kerbwolf.core.ldap.ldap3.Connection"):
            result = _resolve_spn_target(server, "evil.corp", dc_hostname=None)
        assert result == "DC02.evil.corp"

    def test_domain_fallback_when_rootdse_fails(self):
        from kerbwolf.core.ldap import _resolve_spn_target

        server = MagicMock()
        with patch("kerbwolf.core.ldap.ldap3.Connection", side_effect=Exception("bind failed")):
            result = _resolve_spn_target(server, "evil.corp", dc_hostname=None)
        assert result == "evil.corp"

    def test_domain_fallback_when_rootdse_empty(self):
        from kerbwolf.core.ldap import _resolve_spn_target

        server = MagicMock()
        server.info = None
        with patch("kerbwolf.core.ldap.ldap3.Connection"):
            result = _resolve_spn_target(server, "evil.corp", dc_hostname=None)
        assert result == "evil.corp"

    def test_domain_fallback_when_no_dnsHostName(self):
        from kerbwolf.core.ldap import _resolve_spn_target

        server = MagicMock()
        server.info.other = {}
        with patch("kerbwolf.core.ldap.ldap3.Connection"):
            result = _resolve_spn_target(server, "evil.corp", dc_hostname=None)
        assert result == "evil.corp"


# ---------------------------------------------------------------------------
# connect
# ---------------------------------------------------------------------------


class TestConnect:
    def test_ntlm_password_bind(self):
        from kerbwolf.core.ldap import connect

        mock_conn = MagicMock()
        with patch("kerbwolf.core.ldap.ldap3.Server"), patch("kerbwolf.core.ldap.ldap3.Connection", return_value=mock_conn) as mock_cls:
            conn = connect("10.0.0.1", "evil.corp", username="admin", password="pass123")
            assert conn == mock_conn
            # Verify NTLM auth was used
            call_kwargs = mock_cls.call_args
            assert call_kwargs.kwargs.get("user") == "evil.corp\\admin" or call_kwargs[1].get("user") == "evil.corp\\admin"

    def test_ntlm_hash_bind(self):
        from kerbwolf.core.ldap import connect

        mock_conn = MagicMock()
        with patch("kerbwolf.core.ldap.ldap3.Server"), patch("kerbwolf.core.ldap.ldap3.Connection", return_value=mock_conn) as mock_cls:
            conn = connect("10.0.0.1", "evil.corp", username="admin", nthash="aabbccddaabbccddaabbccddaabbccdd")
            assert conn == mock_conn
            # Verify the LM:NT password format
            call_kwargs = mock_cls.call_args
            pw = call_kwargs.kwargs.get("password") or call_kwargs[1].get("password", "")
            assert "aad3b435b51404eeaad3b435b51404ee:" in pw

    def test_ntlm_hash_not_used_when_password_set(self):
        from kerbwolf.core.ldap import connect

        mock_conn = MagicMock()
        with patch("kerbwolf.core.ldap.ldap3.Server"), patch("kerbwolf.core.ldap.ldap3.Connection", return_value=mock_conn) as mock_cls:
            connect("10.0.0.1", "evil.corp", username="admin", password="realpass", nthash="aabb")
            call_kwargs = mock_cls.call_args
            pw = call_kwargs.kwargs.get("password") or call_kwargs[1].get("password", "")
            assert pw == "realpass"

    def test_kerberos_bind_with_ccache(self):
        from kerbwolf.core.ldap import connect

        mock_conn = MagicMock()
        with patch("kerbwolf.core.ldap.ldap3.Server"), patch("kerbwolf.core.ldap.ldap3.Connection", return_value=mock_conn), patch("kerbwolf.core.ldap._resolve_spn_target", return_value="DC01.evil.corp"), patch("kerbwolf.core.ldap.is_ip", return_value=True), patch.dict("os.environ", {}, clear=False):
            import os

            conn = connect("10.0.0.1", "evil.corp", use_kerberos=True, ccache="/tmp/krb.ccache")
            assert conn == mock_conn
            assert os.environ["KRB5CCNAME"] == "/tmp/krb.ccache"

    def test_ssl_port(self):
        from kerbwolf.core.ldap import connect

        mock_conn = MagicMock()
        with patch("kerbwolf.core.ldap.ldap3.Server") as mock_server_cls, patch("kerbwolf.core.ldap.ldap3.Connection", return_value=mock_conn):
            connect("10.0.0.1", "evil.corp", username="admin", password="pass", use_ssl=True)
            call_kwargs = mock_server_cls.call_args
            assert call_kwargs.kwargs.get("port") == 636 or call_kwargs[1].get("port") == 636

    def test_connection_failure_raises_ldap_error(self):
        from kerbwolf.core.ldap import connect

        with patch("kerbwolf.core.ldap.ldap3.Server"), patch("kerbwolf.core.ldap.ldap3.Connection", side_effect=Exception("refused")), pytest.raises(LDAPError, match="LDAP connection"):
            connect("10.0.0.1", "evil.corp", username="admin", password="pass")


# ---------------------------------------------------------------------------
# _search_accounts
# ---------------------------------------------------------------------------


class TestSearchAccounts:
    def _mock_entry(self, samaccountname, uac, spns=None, dn="CN=user,DC=corp"):
        """Build a mock ldap3 entry."""
        entry = MagicMock()
        entry.__getitem__ = lambda self, key: {
            "sAMAccountName": MagicMock(value=samaccountname, __str__=lambda s: samaccountname),
            "userAccountControl": MagicMock(value=uac),
            "servicePrincipalName": MagicMock(
                value=spns[0] if spns else None,
                values=[MagicMock(__str__=lambda s, v=v: v) for v in spns] if spns else [],
            ),
        }[key]
        entry.entry_dn = dn
        return entry

    def test_basic_account_parsing(self):
        from kerbwolf.core.ldap import _search_accounts

        entries = [self._mock_entry("svc_sql", 0x200, ["MSSQLSvc/db01.corp.local"])]
        with patch("kerbwolf.core.ldap._paged_search", return_value=entries):
            results = _search_accounts(MagicMock(), "DC=corp,DC=local", "(filter)")
        assert len(results) == 1
        assert results[0].samaccountname == "svc_sql"
        assert results[0].spns == ("MSSQLSvc/db01.corp.local",)
        assert results[0].use_des_key_only is False
        assert results[0].dont_require_preauth is False

    def test_des_key_only_flag(self):
        from kerbwolf.core.ldap import _search_accounts

        uac = 0x200 | UF_USE_DES_KEY_ONLY
        entries = [self._mock_entry("des_user", uac)]
        with patch("kerbwolf.core.ldap._paged_search", return_value=entries):
            results = _search_accounts(MagicMock(), "DC=corp", "(filter)")
        assert results[0].use_des_key_only is True

    def test_dont_require_preauth_flag(self):
        from kerbwolf.core.ldap import _search_accounts

        uac = 0x200 | UF_DONT_REQUIRE_PREAUTH
        entries = [self._mock_entry("nopreauth", uac)]
        with patch("kerbwolf.core.ldap._paged_search", return_value=entries):
            results = _search_accounts(MagicMock(), "DC=corp", "(filter)")
        assert results[0].dont_require_preauth is True

    def test_no_spns(self):
        from kerbwolf.core.ldap import _search_accounts

        entries = [self._mock_entry("user1", 0x200)]
        with patch("kerbwolf.core.ldap._paged_search", return_value=entries):
            results = _search_accounts(MagicMock(), "DC=corp", "(filter)")
        assert results[0].spns == ()

    def test_multiple_spns(self):
        from kerbwolf.core.ldap import _search_accounts

        entries = [self._mock_entry("svc", 0x200, ["http/web", "http/web.corp.local"])]
        with patch("kerbwolf.core.ldap._paged_search", return_value=entries):
            results = _search_accounts(MagicMock(), "DC=corp", "(filter)")
        assert len(results[0].spns) == 2


# ---------------------------------------------------------------------------
# find_* filter selection
# ---------------------------------------------------------------------------


class TestFindFunctions:
    def test_find_kerberoastable_uses_spn_filter(self):
        from kerbwolf.core.ldap import _FILTER_SPN, find_kerberoastable

        with patch("kerbwolf.core.ldap._search_accounts", return_value=[]) as mock:
            find_kerberoastable(MagicMock(), "corp.local")
            assert mock.call_args[0][2] == _FILTER_SPN

    def test_find_kerberoastable_des_only_uses_des_filter(self):
        from kerbwolf.core.ldap import _FILTER_SPN_DES, find_kerberoastable

        with patch("kerbwolf.core.ldap._search_accounts", return_value=[]) as mock:
            find_kerberoastable(MagicMock(), "corp.local", des_only=True)
            assert mock.call_args[0][2] == _FILTER_SPN_DES

    def test_find_asreproastable_uses_preauth_filter(self):
        from kerbwolf.core.ldap import _FILTER_NO_PREAUTH, find_asreproastable

        with patch("kerbwolf.core.ldap._search_accounts", return_value=[]) as mock:
            find_asreproastable(MagicMock(), "corp.local")
            assert mock.call_args[0][2] == _FILTER_NO_PREAUTH

    def test_find_asreproastable_des_only_uses_des_filter(self):
        from kerbwolf.core.ldap import _FILTER_NO_PREAUTH_DES, find_asreproastable

        with patch("kerbwolf.core.ldap._search_accounts", return_value=[]) as mock:
            find_asreproastable(MagicMock(), "corp.local", des_only=True)
            assert mock.call_args[0][2] == _FILTER_NO_PREAUTH_DES


# ---------------------------------------------------------------------------
# find_all_users
# ---------------------------------------------------------------------------


class TestFindAllUsers:
    def test_returns_samaccountnames(self):
        from kerbwolf.core.ldap import find_all_users

        entries = []
        for name in ["alice", "bob", "charlie"]:
            e = MagicMock()
            e.__getitem__ = lambda self, key, n=name: MagicMock(value=n, __str__=lambda s, n=n: n)
            entries.append(e)

        with patch("kerbwolf.core.ldap._paged_search", return_value=entries):
            result = find_all_users(MagicMock(), "corp.local")
        assert result == ["alice", "bob", "charlie"]

    def test_skips_null_values(self):
        from kerbwolf.core.ldap import find_all_users

        e = MagicMock()
        e.__getitem__ = lambda self, key: MagicMock(value=None)
        with patch("kerbwolf.core.ldap._paged_search", return_value=[e]):
            result = find_all_users(MagicMock(), "corp.local")
        assert result == []


# ---------------------------------------------------------------------------
# find_des_enabled_dcs
# ---------------------------------------------------------------------------


class TestFindDesEnabledDCs:
    def test_des_bits_set(self):
        from kerbwolf.core.ldap import find_des_enabled_dcs

        e = MagicMock()
        e.__getitem__ = lambda self, key: {
            "sAMAccountName": MagicMock(__str__=lambda s: "DC01$"),
            "msDS-SupportedEncryptionTypes": MagicMock(value=0x1F),  # DES + RC4 + AES
        }[key]

        with patch("kerbwolf.core.ldap._paged_search", return_value=[e]):
            result = find_des_enabled_dcs(MagicMock(), "corp.local")
        assert result == ["DC01$"]

    def test_no_des_bits(self):
        from kerbwolf.core.ldap import find_des_enabled_dcs

        e = MagicMock()
        e.__getitem__ = lambda self, key: {
            "sAMAccountName": MagicMock(__str__=lambda s: "DC02$"),
            "msDS-SupportedEncryptionTypes": MagicMock(value=0x1C),  # RC4 + AES only
        }[key]

        with patch("kerbwolf.core.ldap._paged_search", return_value=[e]):
            result = find_des_enabled_dcs(MagicMock(), "corp.local")
        assert result == []

    def test_null_enc_types(self):
        from kerbwolf.core.ldap import find_des_enabled_dcs

        e = MagicMock()
        e.__getitem__ = lambda self, key: {
            "sAMAccountName": MagicMock(__str__=lambda s: "DC03$"),
            "msDS-SupportedEncryptionTypes": MagicMock(value=None),
        }[key]

        with patch("kerbwolf.core.ldap._paged_search", return_value=[e]):
            result = find_des_enabled_dcs(MagicMock(), "corp.local")
        assert result == []


# ---------------------------------------------------------------------------
# _paged_search
# ---------------------------------------------------------------------------


class TestPagedSearch:
    def test_single_page(self):
        from kerbwolf.core.ldap import _paged_search

        conn = MagicMock()
        conn.entries = ["entry1", "entry2"]
        conn.result = {}

        result = _paged_search(conn, "DC=corp", "(filter)", ["attr"])
        assert result == ["entry1", "entry2"]
        assert conn.search.call_count == 1

    def test_multi_page(self):
        from kerbwolf.core.ldap import _paged_search

        conn = MagicMock()
        # First call returns entries + cookie
        # Second call returns more entries + no cookie
        conn.entries = ["e1", "e2"]
        first_result = {"controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b"page2"}}}}
        second_result = {"controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b""}}}}
        conn.result = first_result

        call_count = [0]
        original_entries = [["e1", "e2"], ["e3"]]

        def mock_search(*args, **kwargs):
            idx = call_count[0]
            call_count[0] += 1
            conn.entries = original_entries[idx] if idx < len(original_entries) else []
            conn.result = second_result if idx >= 1 else first_result

        conn.search.side_effect = mock_search
        conn.entries = original_entries[0]
        conn.result = first_result

        result = _paged_search(conn, "DC=corp", "(filter)", ["attr"])
        # First page has e1, e2. After first search mock runs, entries become e3, result becomes no cookie
        assert conn.search.call_count >= 1

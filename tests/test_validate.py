"""Tests for CLI _validate() functions - argument combo checks before network calls."""

import pytest

# ---------------------------------------------------------------------------
# kw-roast validation
# ---------------------------------------------------------------------------


class TestKwRoastValidate:
    def _validate(self, argv):
        from kerbwolf.cli.kerberoast import _build_parser, _validate
        from kerbwolf.log import Logger

        args = _build_parser().parse_args(argv)
        _validate(args, Logger())

    def test_user_without_password_or_hash_exits(self):
        with pytest.raises(SystemExit):
            self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "admin", "-t", "spn"])

    def test_ldap_without_auth_exits(self):
        with pytest.raises(SystemExit):
            self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "--ldap"])

    def test_ldap_all_without_auth_exits(self):
        with pytest.raises(SystemExit):
            self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "--ldap-all"])

    def test_no_targets_and_no_ldap_exits(self):
        with pytest.raises(SystemExit):
            self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "admin", "-p", "pass"])

    def test_targets_with_ntlm_ok(self):
        # Should not raise
        self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "admin", "-p", "pass", "-t", "spn"])

    def test_ldap_with_ntlm_ok(self):
        self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "admin", "-p", "pass", "--ldap"])

    def test_ldap_with_kerberos_ok(self):
        self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-k", "--ldap"])

    def test_no_preauth_without_targets_exits(self):
        """--no-preauth still needs targets."""
        with pytest.raises(SystemExit):
            self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "--no-preauth", "vuln_user"])

    def test_no_preauth_with_targets_ok(self):
        self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "--no-preauth", "vuln_user", "-t", "spn"])

    def test_user_with_hash_ok(self):
        self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "admin", "-H", ":aabbccddaabbccddaabbccddaabbccdd", "-t", "spn"])

    def test_user_with_kerberos_no_password_ok(self):
        """With -k, -u alone is OK (Kerberos auth, no password needed for validation)."""
        self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "admin", "-k", "-t", "spn"])


# ---------------------------------------------------------------------------
# kw-asrep validation
# ---------------------------------------------------------------------------


class TestKwAsrepValidate:
    def _validate(self, argv):
        from kerbwolf.cli.asreproast import _build_parser, _validate
        from kerbwolf.log import Logger

        args = _build_parser().parse_args(argv)
        _validate(args, Logger())

    def test_user_without_password_exits(self):
        with pytest.raises(SystemExit):
            self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "admin", "-t", "user1"])

    def test_ldap_without_auth_exits(self):
        with pytest.raises(SystemExit):
            self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "--ldap"])

    def test_no_targets_no_ldap_exits(self):
        with pytest.raises(SystemExit):
            self._validate(["-d", "D", "--dc-ip", "1.2.3.4"])

    def test_targets_ok(self):
        self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-t", "user1"])

    def test_ldap_with_ntlm_ok(self):
        self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "admin", "-p", "pass", "--ldap"])

    def test_ldap_with_kerberos_ok(self):
        self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-k", "--ldap"])

    def test_targets_and_ldap_ok(self):
        self._validate(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "admin", "-p", "pass", "-t", "user1", "--ldap"])


# ---------------------------------------------------------------------------
# kw-tgt _resolve_enctype
# ---------------------------------------------------------------------------


class TestResolveEnctype:
    def _resolve(self, argv):
        from kerbwolf.cli.gettgt import _build_parser, _resolve_enctype
        from kerbwolf.log import Logger

        args = _build_parser().parse_args(argv)
        return _resolve_enctype(args, Logger())

    def test_password_default_rc4(self):
        assert self._resolve(["-d", "D", "-u", "u", "-p", "pass"]) == "rc4"

    def test_password_with_explicit_enctype(self):
        assert self._resolve(["-d", "D", "-u", "u", "-p", "pass", "-e", "aes256"]) == "aes256"

    def test_hash_implies_rc4(self):
        assert self._resolve(["-d", "D", "-u", "u", "-H", ":aabb"]) == "rc4"

    def test_hash_ignores_explicit_enctype(self, capsys):
        """NT hash always means RC4, even if -e says otherwise."""
        result = self._resolve(["-d", "D", "-u", "u", "-H", ":aabb", "-e", "aes256"])
        assert result == "rc4"

    def test_rc4_key_implies_rc4(self):
        assert self._resolve(["-d", "D", "-u", "u", "--rc4-key", "aa" * 16]) == "rc4"

    def test_aes256_key_implies_aes256(self):
        assert self._resolve(["-d", "D", "-u", "u", "--aes256-key", "bb" * 32]) == "aes256"

    def test_aes128_key_implies_aes128(self):
        assert self._resolve(["-d", "D", "-u", "u", "--aes128-key", "cc" * 16]) == "aes128"

    def test_des_md5_key_implies_des_cbc_md5(self):
        assert self._resolve(["-d", "D", "-u", "u", "--des-md5-key", "dd" * 8]) == "des-cbc-md5"

    def test_des_crc_key_implies_des_cbc_crc(self):
        assert self._resolve(["-d", "D", "-u", "u", "--des-crc-key", "ee" * 8]) == "des-cbc-crc"

    def test_aes256_key_ignores_explicit_enctype(self, capsys):
        """Key type forces etype, -e is ignored."""
        result = self._resolve(["-d", "D", "-u", "u", "--aes256-key", "bb" * 32, "-e", "rc4"])
        assert result == "aes256"

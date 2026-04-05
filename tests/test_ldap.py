"""Tests for kerbwolf.core.ldap - LDAP enumeration and modification."""


# ---------------------------------------------------------------------------
# _base_dn
# ---------------------------------------------------------------------------


class TestBaseDn:
    def test_simple_domain(self):
        from kerbwolf.core.ldap import _base_dn

        assert _base_dn("domain.local") == "DC=domain,DC=local"

    def test_three_part_domain(self):
        from kerbwolf.core.ldap import _base_dn

        assert _base_dn("sub.domain.local") == "DC=sub,DC=domain,DC=local"

    def test_single_part(self):
        from kerbwolf.core.ldap import _base_dn

        assert _base_dn("LOCAL") == "DC=LOCAL"


# ---------------------------------------------------------------------------
# LDAP filter constants
# ---------------------------------------------------------------------------


class TestLdapFilters:
    def test_spn_filter_excludes_disabled(self):
        from kerbwolf.core.ldap import _FILTER_SPN

        assert "1.2.840.113556.1.4.803:=2" in _FILTER_SPN

    def test_spn_filter_requires_spn(self):
        from kerbwolf.core.ldap import _FILTER_SPN

        assert "servicePrincipalName=*" in _FILTER_SPN

    def test_des_filter_has_uac_bit(self):
        from kerbwolf.core.ldap import _FILTER_SPN_DES

        assert "2097152" in _FILTER_SPN_DES  # UF_USE_DES_KEY_ONLY

    def test_no_preauth_filter_has_uac_bit(self):
        from kerbwolf.core.ldap import _FILTER_NO_PREAUTH

        assert "4194304" in _FILTER_NO_PREAUTH  # UF_DONT_REQUIRE_PREAUTH

    def test_dc_filter(self):
        from kerbwolf.core.ldap import _FILTER_DCS

        assert "8192" in _FILTER_DCS  # UF_SERVER_TRUST_ACCOUNT

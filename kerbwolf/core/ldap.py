"""LDAP enumeration and Active Directory attribute modification.

Uses ldap3 (dev branch) for full LDAP support including paged searches
and modification operations.
"""

from __future__ import annotations

import logging
import os
import struct

import ldap3

from kerbwolf.core.resolve import is_ip
from kerbwolf.models import (
    UF_DONT_REQUIRE_PREAUTH,
    UF_USE_DES_KEY_ONLY,
    LDAPError,
    TargetAccount,
    TimeroastAccount,
)

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LDAP filter templates
# ---------------------------------------------------------------------------

_FILTER_SPN = "(&(servicePrincipalName=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"
_FILTER_SPN_DES = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=2097152)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"
_FILTER_NO_PREAUTH = "(&(UserAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"
_FILTER_NO_PREAUTH_DES = "(&(UserAccountControl:1.2.840.113556.1.4.803:=4194304)(UserAccountControl:1.2.840.113556.1.4.803:=2097152)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"
_FILTER_DCS = "(UserAccountControl:1.2.840.113556.1.4.803:=8192)"
_FILTER_ALL_USERS = "(&(objectCategory=person)(objectClass=user)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"

# Timeroasting: computer and gMSA objects respond to MS-SNTP.
# Tested on Server 2022 (Build 20348) and Server 2025 (Build 26100):
#   computer                              → YES (MD5 + SHA512)
#   msDS-GroupManagedServiceAccount (gMSA) → YES (MD5 + SHA512)
#   msDS-ManagedServiceAccount (MSA)       → NO
#   msDS-DelegatedManagedServiceAccount    → NO
#   user (even with $ in sAMAccountName)   → NO
# computer has objectCategory=computer, gMSA has objectCategory=ms-DS-Group-Managed-Service-Account.
# Use objectClass to match both with a single OR filter.
# No UAC filter - disabled accounts may still have hashes. The NTP probe
# itself determines what actually responds.
_FILTER_TIMEROASTABLE = "(|(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))"

_ATTRS = ["sAMAccountName", "servicePrincipalName", "userAccountControl"]
_PAGE_SIZE = 1000


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------


def connect(
    dc_ip: str,
    domain: str,
    username: str = "",
    password: str = "",
    *,
    nthash: str = "",
    use_ssl: bool = False,
    use_kerberos: bool = False,
    ccache: str | None = None,
    dc_hostname: str | None = None,
) -> ldap3.Connection:
    """Establish an authenticated LDAP(S) connection.

    Auth modes:
    - **NTLM password**: *username* + *password*
    - **NTLM hash**: *username* + *nthash* (passed as password in LM:NT format)
    - **Kerberos**: *use_kerberos=True* + *ccache* (or ``KRB5CCNAME``)

    For Kerberos, *dc_hostname* provides the DC FQDN for GSSAPI SPN
    construction.  If not provided and *dc_ip* is an IP address, the
    hostname is auto-detected from LDAP RootDSE or falls back to *domain*.
    """
    port = 636 if use_ssl else 389
    _log.info("LDAP connecting to %s:%d (ssl=%s)", dc_ip, port, use_ssl)
    server = ldap3.Server(dc_ip, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)

    try:
        if use_kerberos:
            if ccache:
                os.environ["KRB5CCNAME"] = ccache
            sasl_target = (_resolve_spn_target(server, domain, dc_hostname),) if is_ip(dc_ip) else None
            _log.info("LDAP GSSAPI bind (SPN: ldap/%s)", sasl_target[0] if sasl_target else dc_ip)
            conn = ldap3.Connection(server, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS, sasl_credentials=sasl_target, auto_bind=True)
        else:
            user_dn = f"{domain}\\{username}"
            auth_password = password
            if nthash and not password:
                auth_password = f"aad3b435b51404eeaad3b435b51404ee:{nthash}"
            _log.info("LDAP NTLM bind as %s", user_dn)
            conn = ldap3.Connection(server, user=user_dn, password=auth_password, authentication=ldap3.NTLM, auto_bind=True)
    except Exception as exc:
        msg = f"LDAP connection to {dc_ip} failed: {exc}"
        raise LDAPError(msg) from exc

    return conn


def _resolve_spn_target(server: ldap3.Server, domain: str, dc_hostname: str | None) -> str:
    """Determine the DC FQDN for GSSAPI SPN construction.

    Resolution chain:
    1. ``--dc-hostname`` if provided (explicit user override)
    2. RootDSE ``dnsHostName`` via anonymous bind (most reliable auto-detection)
    3. Domain name from ``-d`` (last resort)
    """
    if dc_hostname:
        _log.info("SPN target: %s (--dc-hostname)", dc_hostname)
        return dc_hostname
    try:
        with ldap3.Connection(server, auto_bind=True):
            pass
        if server.info and server.info.other.get("dnsHostName"):
            hostname = str(server.info.other["dnsHostName"][0])
            _log.info("SPN target: %s (RootDSE)", hostname)
            return hostname
    except Exception:  # noqa: BLE001, S110
        pass
    _log.info("SPN target: %s (domain fallback)", domain)
    return domain


def _base_dn(domain: str) -> str:
    """Convert ``domain.local`` to ``DC=domain,DC=local``."""
    return ",".join(f"DC={part}" for part in domain.split("."))


# ---------------------------------------------------------------------------
# Paged search
# ---------------------------------------------------------------------------


def _paged_search(conn: ldap3.Connection, base_dn: str, ldap_filter: str, attributes: list[str]) -> list:
    """Run a paged LDAP search to handle domains with >1000 results."""
    _log.debug("LDAP search: base=%s filter=%s", base_dn, ldap_filter[:80])
    conn.search(base_dn, ldap_filter, attributes=attributes, paged_size=_PAGE_SIZE)
    results = list(conn.entries)
    page = 1

    cookie = (conn.result or {}).get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
    while cookie:
        page += 1
        conn.search(base_dn, ldap_filter, attributes=attributes, paged_size=_PAGE_SIZE, paged_cookie=cookie)
        results.extend(conn.entries)
        _log.debug("LDAP page %d: %d results so far", page, len(results))
        cookie = (conn.result or {}).get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")

    _log.info("LDAP: %d results", len(results))
    return results


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def find_kerberoastable(conn: ldap3.Connection, domain: str, *, des_only: bool = False) -> list[TargetAccount]:
    """Find accounts with SPNs suitable for kerberoasting."""
    ldap_filter = _FILTER_SPN_DES if des_only else _FILTER_SPN
    return _search_accounts(conn, _base_dn(domain), ldap_filter)


def find_asreproastable(conn: ldap3.Connection, domain: str, *, des_only: bool = False) -> list[TargetAccount]:
    """Find accounts with DONT_REQUIRE_PREAUTH."""
    ldap_filter = _FILTER_NO_PREAUTH_DES if des_only else _FILTER_NO_PREAUTH
    return _search_accounts(conn, _base_dn(domain), ldap_filter)


def find_des_enabled_dcs(conn: ldap3.Connection, domain: str) -> list[str]:
    """Find DCs with DES in msDS-SupportedEncryptionTypes."""
    entries = _paged_search(conn, _base_dn(domain), _FILTER_DCS, ["sAMAccountName", "msDS-SupportedEncryptionTypes"])
    dcs: list[str] = []
    for entry in entries:
        enc_types = entry["msDS-SupportedEncryptionTypes"].value
        if enc_types is not None and int(enc_types) & 0x3:
            dcs.append(str(entry["sAMAccountName"]))
    return dcs


def find_all_users(conn: ldap3.Connection, domain: str) -> list[str]:
    """Enumerate all enabled user accounts with paging."""
    entries = _paged_search(conn, _base_dn(domain), _FILTER_ALL_USERS, ["sAMAccountName"])
    return [str(entry["sAMAccountName"]) for entry in entries if entry["sAMAccountName"].value]


def find_timeroastable(conn: ldap3.Connection, domain: str) -> list[TimeroastAccount]:
    """Find all enabled computer and gMSA accounts (timeroastable via MS-SNTP).

    Both ``computer`` and ``msDS-GroupManagedServiceAccount`` (gMSA) objects
    respond to MS-SNTP - both have ``objectCategory=computer`` so a single
    filter catches them.  MSAs, dMSAs, and user objects do NOT respond
    (confirmed on Server 2022/2025).  Trust accounts may respond but
    require a separate query.

    Returns:
        List of ``TimeroastAccount`` with sAMAccountName and RID extracted
        from objectSid.

    """
    entries = _paged_search(
        conn,
        _base_dn(domain),
        _FILTER_TIMEROASTABLE,
        ["sAMAccountName", "objectSid"],
    )
    results: list[TimeroastAccount] = []
    for entry in entries:
        name = entry["sAMAccountName"].value
        sid_raw = entry["objectSid"].raw_values
        if name and sid_raw:
            rid = _extract_rid(sid_raw[0])
            results.append(TimeroastAccount(samaccountname=str(name), rid=rid))
    return results


def _extract_rid(sid_bytes: bytes) -> int:
    """Extract the RID (last 4 bytes, little-endian) from a binary objectSid."""
    return struct.unpack("<I", sid_bytes[-4:])[0]


def _search_accounts(conn: ldap3.Connection, base_dn: str, ldap_filter: str) -> list[TargetAccount]:
    """Run a paged LDAP search and return ``TargetAccount`` records."""
    entries = _paged_search(conn, base_dn, ldap_filter, _ATTRS)
    results: list[TargetAccount] = []
    for entry in entries:
        uac = int(entry["userAccountControl"].value or 0)
        spns_raw = entry["servicePrincipalName"].values if entry["servicePrincipalName"].value else []
        results.append(
            TargetAccount(
                samaccountname=str(entry["sAMAccountName"]),
                dn=str(entry.entry_dn),
                spns=tuple(str(s) for s in spns_raw),
                uac=uac,
                use_des_key_only=bool(uac & UF_USE_DES_KEY_ONLY),
                dont_require_preauth=bool(uac & UF_DONT_REQUIRE_PREAUTH),
            )
        )
    return results

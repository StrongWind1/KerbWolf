"""Data models, enumerations, and constants used across the package."""

from __future__ import annotations

import enum
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Encryption types - every etype Windows supports for Kerberos
# ---------------------------------------------------------------------------


class EncryptionType(enum.IntEnum):
    """Kerberos encryption types supported by Windows.

    DES types are disabled by default since Server 2008 but can be
    re-enabled via GPO.  RC4 is deprecated since Server 2016 and
    disabled in Server 2025.
    """

    DES_CBC_CRC = 1
    DES_CBC_MD5 = 3
    AES128_CTS_HMAC_SHA1_96 = 17
    AES256_CTS_HMAC_SHA1_96 = 18
    RC4_HMAC = 23

    @property
    def is_des(self) -> bool:
        """Return True if this is a DES encryption type."""
        return self in {EncryptionType.DES_CBC_CRC, EncryptionType.DES_CBC_MD5}

    @property
    def is_aes(self) -> bool:
        """Return True if this is an AES encryption type."""
        return self in {EncryptionType.AES128_CTS_HMAC_SHA1_96, EncryptionType.AES256_CTS_HMAC_SHA1_96}


# Friendly CLI name → EncryptionType mapping.
ETYPE_BY_NAME: dict[str, EncryptionType] = {
    "des-cbc-crc": EncryptionType.DES_CBC_CRC,
    "des-cbc-md5": EncryptionType.DES_CBC_MD5,
    "rc4": EncryptionType.RC4_HMAC,
    "aes128": EncryptionType.AES128_CTS_HMAC_SHA1_96,
    "aes256": EncryptionType.AES256_CTS_HMAC_SHA1_96,
}


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class TransportProtocol(enum.StrEnum):
    """Transport protocol for Kerberos requests."""

    UDP = "udp"
    TCP = "tcp"


# ---------------------------------------------------------------------------
# Hash output format
# ---------------------------------------------------------------------------


class HashFormat(enum.StrEnum):
    """Output format for crackable hashes."""

    HASHCAT = "hashcat"
    JOHN = "john"


# ---------------------------------------------------------------------------
# Hashcat mode numbers
#
# DES modes (etype 1, 3) are proposed new modules that brute-force
# the 56-bit DES key directly, not the password.
# ---------------------------------------------------------------------------


class HashcatMode(enum.IntEnum):
    """Hashcat mode numbers for Kerberos hash types."""

    # TGS-REP Roast (Kerberoast)
    KRB5_TGS_DES_CBC_CRC = -1  # proposed
    KRB5_TGS_DES_CBC_MD5 = -3  # proposed
    KRB5_TGS_AES128 = 19600
    KRB5_TGS_AES256 = 19700
    KRB5_TGS_RC4 = 13100

    # AS-REP Roast
    KRB5_ASREP_DES_CBC_CRC = -2  # proposed
    KRB5_ASREP_DES_CBC_MD5 = -4  # proposed
    KRB5_ASREP_AES128 = 32100
    KRB5_ASREP_AES256 = 32200
    KRB5_ASREP_RC4 = 18200

    # AS-REQ Pre-Auth
    KRB5_PA_DES_CBC_CRC = -5  # proposed
    KRB5_PA_DES_CBC_MD5 = -6  # proposed
    KRB5_PA_AES128 = 19800
    KRB5_PA_AES256 = 19900
    KRB5_PA_RC4 = 7500

    # Timeroasting (MS-SNTP)  # noqa: ERA001
    SNTP_MS = 31300

    # NTLM
    NTLMV1 = 5500
    NTLMV2 = 5600


# ---------------------------------------------------------------------------
# UserAccountControl flag constants
# ---------------------------------------------------------------------------

UF_ACCOUNTDISABLE = 0x0000_0002
UF_WORKSTATION_TRUST_ACCOUNT = 0x0000_1000
UF_SERVER_TRUST_ACCOUNT = 0x0000_2000
UF_DONT_EXPIRE_PASSWORD = 0x0001_0000
UF_USE_DES_KEY_ONLY = 0x0020_0000
UF_DONT_REQUIRE_PREAUTH = 0x0040_0000
UF_TRUSTED_FOR_DELEGATION = 0x0008_0000

# XOR mask to swap SERVER_TRUST_ACCOUNT ↔ WORKSTATION_TRUST_ACCOUNT.
UF_TRUST_ACCOUNT_SWAP_MASK = UF_SERVER_TRUST_ACCOUNT | UF_WORKSTATION_TRUST_ACCOUNT

# ---------------------------------------------------------------------------
# Key hex lengths (characters, not bytes)
# ---------------------------------------------------------------------------

DES_KEY_HEX_LEN = 16  # 8 bytes
RC4_KEY_HEX_LEN = 32  # 16 bytes
AES128_KEY_HEX_LEN = 32  # 16 bytes
AES256_KEY_HEX_LEN = 64  # 32 bytes

# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RoastResult:
    """One crackable hash extracted from a Kerberos exchange."""

    username: str
    realm: str
    spn: str
    etype: int
    hash_string: str
    hashcat_mode: int


@dataclass(frozen=True)
class TargetAccount:
    """Account discovered via LDAP enumeration."""

    samaccountname: str
    dn: str
    spns: tuple[str, ...] = ()
    uac: int = 0
    use_des_key_only: bool = False
    dont_require_preauth: bool = False


@dataclass(frozen=True)
class TimeroastAccount:
    """Computer or gMSA account discovered via LDAP for timeroasting.

    Timeroastable object types (confirmed on Server 2022/2025):
        - computer (objectCategory=computer)
        - gMSA (msDS-GroupManagedServiceAccount, also objectCategory=computer)

    NOT timeroastable:
        - user (even with $ in sAMAccountName)
        - MSA (msDS-ManagedServiceAccount)
        - dMSA (msDS-DelegatedManagedServiceAccount)
    """

    samaccountname: str  # e.g. "DC01$"
    rid: int  # extracted from objectSid (last 4 bytes LE)


@dataclass
class KerberosCredential:
    """Credential material for Kerberos authentication."""

    username: str
    domain: str
    password: str | None = None
    nthash: bytes = b""
    aes128_key: bytes = b""
    aes256_key: bytes = b""
    des_key: bytes = b""


# ---------------------------------------------------------------------------
# Kerberos context (populated once at CLI startup)
# ---------------------------------------------------------------------------


@dataclass
class KerberosContext:
    """Resolved connection context for all CLI tools.

    Populated once at startup from ccache, DNS, and CLI flags.
    Passed to attack functions and LDAP connections.
    """

    domain: str
    """Domain FQDN (lowercase), e.g. ``contoso.com``."""

    realm: str
    """Kerberos realm (uppercase), e.g. ``CONTOSO.COM``."""

    dc_ip: str
    """Domain controller IP address for transport."""

    dc_hostname: str | None = None
    """DC FQDN for GSSAPI SPN (e.g. ``DC01.contoso.com``).  ``None`` if only an IP is known."""

    username: str | None = None
    """Username from ``-u`` or ccache principal."""

    timeout: float = 10.0
    """Network timeout in seconds for KDC communication."""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class KerbWolfError(Exception):
    """Base exception for all kerbwolf errors."""


class KDCError(KerbWolfError):
    """Raised when the KDC returns an error we cannot recover from."""

    def __init__(self, error_code: int, message: str = "") -> None:
        """Create a KDC error with the given Kerberos error code."""
        self.error_code = error_code
        super().__init__(message or f"KDC error {error_code}")


class LDAPError(KerbWolfError):
    """Raised when an LDAP operation fails."""

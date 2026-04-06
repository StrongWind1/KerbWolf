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

from kerbwolf.core.capture import AttackType, CapturedHash, parse_pcap
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
from kerbwolf.models import HashcatMode, HashFormat, RoastResult

_log = logging.getLogger(__name__)


def extract_from_pcap(
    path: str,
    *,
    hash_format: HashFormat = HashFormat.HASHCAT,
) -> list[RoastResult]:
    """Parse a pcap/pcapng file and extract all roastable hashes.

    Extracts Kerberos hashes (port 88) and MS-SNTP timeroast hashes
    (port 123) from the same capture.

    Pass ``"-"`` as *path* to read from stdin.
    """
    captured = parse_pcap(path)
    _log.debug("Parsed %s: %d raw hashes", path, len(captured))
    return [_captured_to_result(h, hash_format) for h in captured]


def _captured_to_result(h: CapturedHash, fmt: HashFormat) -> RoastResult:
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

    if h.attack == AttackType.AS_REQ:
        hash_string = format_pa_hash(cipher, h.etype, h.username, h.realm, fmt=fmt)
        mode = pa_hashcat_mode(h.etype)
    elif h.attack == AttackType.AS_REP:
        hash_string = format_asrep_hash_raw(cipher, h.etype, h.username, h.realm, fmt=fmt)
        mode = asrep_hashcat_mode(h.etype)
    else:  # TGS-REP
        hash_string = format_tgs_hash_raw(cipher, h.etype, h.username, h.realm, h.spn, fmt=fmt)
        mode = tgs_hashcat_mode(h.etype)

    return RoastResult(
        username=h.username,
        realm=h.realm,
        spn=h.spn,
        etype=h.etype,
        hash_string=hash_string,
        hashcat_mode=mode,
    )

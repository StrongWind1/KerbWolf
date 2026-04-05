"""Ticket decryption, PAC extraction, and EncTicketPart parsing."""

from __future__ import annotations

from impacket.krb5.asn1 import (
    AD_IF_RELEVANT,
    EncTicketPart,
)
from impacket.krb5.crypto import Key
from pyasn1.codec.der import decoder

from kerbwolf.core.crypto import ENCTYPE_TABLE

# AD-IF-RELEVANT type constant for PAC.
_AD_WIN2K_PAC = 128


def decrypt_ticket(cipher_bytes: bytes, key: Key, etype: int) -> bytes:
    """Decrypt a ticket's ``enc-part`` cipher with Key Usage 2.

    Returns:
        Raw DER-encoded ``EncTicketPart`` bytes.

    """
    cipher_cls = ENCTYPE_TABLE[etype]
    return cipher_cls.decrypt(key, 2, cipher_bytes)


def parse_enc_ticket_part(decrypted: bytes) -> EncTicketPart:
    """Decode raw bytes into an ``EncTicketPart`` ASN.1 structure."""
    return decoder.decode(decrypted, asn1Spec=EncTicketPart())[0]


def extract_session_key(enc_ticket_part: EncTicketPart) -> Key:
    """Extract the session key from a decrypted ``EncTicketPart``."""
    key_type = int(enc_ticket_part["key"]["keytype"])
    key_value = enc_ticket_part["key"]["keyvalue"].asOctets()
    return Key(key_type, key_value)


def extract_pac(decrypted_ticket: bytes) -> bytes | None:
    """Extract raw PAC bytes from a decrypted ``EncTicketPart``.

    Walks the ``authorization-data`` looking for an ``AD-IF-RELEVANT``
    entry containing an ``AD-WIN2K-PAC`` (type 128).

    Returns:
        Raw PAC bytes, or ``None`` if no PAC is found.

    """
    enc_ticket_part = parse_enc_ticket_part(decrypted_ticket)

    if not enc_ticket_part["authorization-data"]:
        return None

    for ad_entry in enc_ticket_part["authorization-data"]:
        ad_type = int(ad_entry["ad-type"])
        if ad_type == 1:  # AD-IF-RELEVANT
            ad_if_relevant = decoder.decode(ad_entry["ad-data"], asn1Spec=AD_IF_RELEVANT())[0]
            for inner in ad_if_relevant:
                if int(inner["ad-type"]) == _AD_WIN2K_PAC:
                    return bytes(inner["ad-data"])

    return None

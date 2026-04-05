"""TGS-REQ message builder with U2U and encryption-type control.

Builds Kerberos TGS-REQ messages for:
- Standard service ticket requests (configurable etype)
- User-to-User (U2U) requests with additional-tickets field
- DES-forced TGS requests for DES kerberoasting
"""

from __future__ import annotations

import datetime
import logging
import secrets
from typing import Any

from impacket.krb5 import constants as krb_constants
from impacket.krb5.asn1 import (
    AP_REQ,
    AS_REP,
    TGS_REP,
    TGS_REQ,
    Authenticator,
    EncTGSRepPart,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.asn1 import (
    Ticket as TicketAsn1,
)
from impacket.krb5.crypto import Key
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from kerbwolf.core.transport import send_receive
from kerbwolf.models import TransportProtocol

_log = logging.getLogger(__name__)

# Default etypes sent in TGS-REQ when none are specified.
_DEFAULT_TGS_ETYPES = (
    int(krb_constants.EncryptionTypes.rc4_hmac.value),
    int(krb_constants.EncryptionTypes.des3_cbc_sha1_kd.value),
    int(krb_constants.EncryptionTypes.des_cbc_md5.value),
    int(krb_constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
)


# ---------------------------------------------------------------------------
# Low-level TGS-REQ builder
# ---------------------------------------------------------------------------


def build_tgsreq(
    tgt_bytes: bytes,
    session_key: Key,
    cipher_cls: Any,  # noqa: ANN401
    *,
    service: str,
    domain: str,
    etypes: tuple[int, ...] | None = None,
    u2u: bool = False,
    additional_ticket_bytes: bytes | None = None,
) -> bytes:
    """Build a TGS-REQ message with full control over etype and U2U.

    Args:
        tgt_bytes: Raw AS-REP or TGS-REP containing the TGT.
        session_key: TGT session key.
        cipher_cls: Cipher class matching *session_key*.
        service: SPN or username for the sname field.
        domain: Domain FQDN (uppercased for realm).
        etypes: Requested encryption types.  ``None`` uses defaults.
        u2u: If ``True``, sets ``enc_tkt_in_skey`` KDC option.
        additional_ticket_bytes: Raw ticket to embed in ``additional-tickets``
            (required for U2U - the TGT whose session key encrypts the result).

    """
    realm = domain.upper()

    # Decode TGT to extract the ticket and client name.
    decoded_tgt = _decode_tgt(tgt_bytes)
    ticket = Ticket()
    ticket.from_asn1(decoded_tgt["ticket"])
    client_name = Principal()
    client_name.from_asn1(decoded_tgt, "crealm", "cname")

    # -- AP-REQ (authenticator encrypted with TGT session key) ----------------
    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = str(decoded_tgt["crealm"])
    seq_set(authenticator, "cname", client_name.components_to_asn1)

    now = datetime.datetime.now(datetime.UTC)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    # Key Usage 7 - TGS-REQ AP-REQ Authenticator.
    encrypted_auth = cipher_cls.encrypt(session_key, 7, encoder.encode(authenticator), None)

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(krb_constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req["ap-options"] = krb_constants.encodeFlags([])
    seq_set(ap_req, "ticket", ticket.to_asn1)
    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher_cls.enctype
    ap_req["authenticator"]["cipher"] = encrypted_auth

    # -- TGS-REQ --------------------------------------------------------------
    tgs_req = TGS_REQ()
    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(krb_constants.ApplicationTagNumbers.TGS_REQ.value)
    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(krb_constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)

    # -- req-body -------------------------------------------------------------
    req_body = seq_set(tgs_req, "req-body")

    opts = [
        krb_constants.KDCOptions.forwardable.value,
        krb_constants.KDCOptions.renewable.value,
        krb_constants.KDCOptions.renewable_ok.value,
        krb_constants.KDCOptions.canonicalize.value,
    ]
    if u2u:
        opts.append(krb_constants.KDCOptions.enc_tkt_in_skey.value)

    req_body["kdc-options"] = krb_constants.encodeFlags(opts)

    server_principal = Principal(service, type=krb_constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(req_body, "sname", server_principal.components_to_asn1)
    req_body["realm"] = realm

    tomorrow = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
    req_body["till"] = KerberosTime.to_asn1(tomorrow)
    req_body["nonce"] = secrets.randbits(31)

    seq_set_iter(req_body, "etype", etypes or _DEFAULT_TGS_ETYPES)

    # -- additional-tickets (for U2U / S4U2Proxy) ----------------------------
    if additional_ticket_bytes is not None:
        add_ticket = _extract_ticket_asn1(additional_ticket_bytes)
        seq_set_iter(req_body, "additional-tickets", (add_ticket,))

    return encoder.encode(tgs_req)


# ---------------------------------------------------------------------------
# High-level: request a service ticket
# ---------------------------------------------------------------------------


def request_tgs(
    tgt_bytes: bytes,
    session_key: Key,
    cipher_cls: Any,  # noqa: ANN401
    *,
    service: str,
    domain: str,
    dc_ip: str,
    etypes: tuple[int, ...] | None = None,
    transport: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
) -> tuple[bytes, Key]:
    """Request a service ticket.

    Returns:
        ``(raw_tgsrep_bytes, new_session_key)``

    """
    _log.debug("TGS-REQ → %s for %s@%s", dc_ip, service, domain.upper())
    message = build_tgsreq(
        tgt_bytes,
        session_key,
        cipher_cls,
        service=service,
        domain=domain,
        etypes=etypes,
    )
    response = send_receive(message, dc_ip, protocol=transport, timeout=timeout)
    new_session_key = _extract_tgs_session_key(response, session_key, cipher_cls)
    _log.debug("TGS-REP ← ticket for %s, session key etype %d", service, new_session_key.enctype)
    return response, new_session_key


# ---------------------------------------------------------------------------
# High-level: request a User-to-User ticket
# ---------------------------------------------------------------------------


def request_u2u(
    tgt_bytes: bytes,
    session_key: Key,
    cipher_cls: Any,  # noqa: ANN401
    *,
    service: str,
    domain: str,
    dc_ip: str,
    additional_ticket_tgt: bytes,
    etypes: tuple[int, ...] | None = None,
    transport: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
) -> tuple[bytes, Key]:
    """Request a User-to-User ticket.

    The resulting TGS is encrypted with the session key of
    *additional_ticket_tgt*, not the service account's long-term key.

    Returns:
        ``(raw_tgsrep_bytes, new_session_key)``

    """
    message = build_tgsreq(
        tgt_bytes,
        session_key,
        cipher_cls,
        service=service,
        domain=domain,
        etypes=etypes,
        u2u=True,
        additional_ticket_bytes=additional_ticket_tgt,
    )
    response = send_receive(message, dc_ip, protocol=transport, timeout=timeout)
    new_session_key = _extract_tgs_session_key(response, session_key, cipher_cls)
    return response, new_session_key


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decode_tgt(tgt_bytes: bytes) -> AS_REP | TGS_REP:
    """Decode raw bytes as AS-REP, falling back to TGS-REP."""
    try:
        return decoder.decode(tgt_bytes, asn1Spec=AS_REP())[0]
    except Exception:  # noqa: BLE001
        return decoder.decode(tgt_bytes, asn1Spec=TGS_REP())[0]


def _extract_ticket_asn1(rep_bytes: bytes) -> TicketAsn1:
    """Extract the ASN.1 ``Ticket`` from an AS-REP or TGS-REP."""
    decoded = _decode_tgt(rep_bytes)
    ticket = Ticket()
    ticket.from_asn1(decoded["ticket"])
    return ticket.to_asn1(TicketAsn1())


def _extract_tgs_session_key(tgs_rep_bytes: bytes, session_key: Key, cipher_cls: Any) -> Key:  # noqa: ANN401
    """Decrypt the TGS-REP enc-part and extract the new session key."""
    tgs_rep = decoder.decode(tgs_rep_bytes, asn1Spec=TGS_REP())[0]
    cipher_text = tgs_rep["enc-part"]["cipher"]

    # Key Usage 8 - TGS-REP encrypted part.
    plaintext = cipher_cls.decrypt(session_key, 8, cipher_text)
    enc_part = decoder.decode(plaintext, asn1Spec=EncTGSRepPart())[0]

    return Key(int(enc_part["key"]["keytype"]), enc_part["key"]["keyvalue"].asOctets())

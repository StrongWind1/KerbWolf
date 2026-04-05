"""Load TGTs from CCache files for pass-the-ticket authentication."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from impacket.krb5.ccache import CCache

from kerbwolf.core.crypto import ENCTYPE_TABLE

if TYPE_CHECKING:
    from impacket.krb5.crypto import Key
from kerbwolf.models import KerbWolfError

_log = logging.getLogger(__name__)


def get_ccache_info(ccache_path: str) -> tuple[str, str]:
    """Extract the username and domain from a ccache file.

    Returns ``(username, domain)`` from the principal ``user@REALM``.
    """
    try:
        ccache = CCache.loadFile(ccache_path)
    except Exception as exc:
        msg = f"Failed to load ccache '{ccache_path}': {exc}"
        raise KerbWolfError(msg) from exc

    pp = ccache.principal.prettyPrint().decode()
    if "@" not in pp:
        msg = f"Cannot parse principal from ccache '{ccache_path}': {pp}"
        raise KerbWolfError(msg)

    username, realm = pp.split("@", 1)
    _log.info("Ccache: %s@%s from %s", username, realm, ccache_path)
    return username, realm.lower()


def load_tgt_from_ccache(ccache_path: str | None = None) -> tuple[bytes, Key, type]:
    """Load a TGT from a ccache file and return the raw TGT + session key + cipher class.

    If *ccache_path* is ``None``, reads from the ``KRB5CCNAME`` environment variable.

    Returns:
        ``(raw_tgt_bytes, session_key, cipher_class)``

    Raises:
        KerbWolfError: If the ccache cannot be loaded or contains no TGT.

    """
    path = ccache_path or os.environ.get("KRB5CCNAME", "")
    if not path:
        msg = "No ccache file specified.  Use -c FILE or set KRB5CCNAME."
        raise KerbWolfError(msg)

    try:
        ccache = CCache.loadFile(path)
    except Exception as exc:
        msg = f"Failed to load ccache '{path}': {exc}"
        raise KerbWolfError(msg) from exc

    # Extract the first TGT (credential for krbtgt/REALM).
    tgt_cred = None
    for cred in ccache.credentials:
        server = cred.header["server"]
        server_name = str(server.prettyPrint())
        if "krbtgt" in server_name:
            tgt_cred = cred
            break

    if tgt_cred is None:
        msg = f"No TGT found in ccache '{path}'."
        raise KerbWolfError(msg)
    _log.info("TGT found for %s", str(tgt_cred.header["server"].prettyPrint()))

    # Convert to raw TGT bytes (AS-REP format) and extract session key.
    # toTGT() is on the Credential object, not CCache.
    try:
        raw_tgt = tgt_cred.toTGT()
        tgt_bytes = raw_tgt["KDC_REP"]
        session_key = raw_tgt["sessionKey"]  # Already a Key object
        cipher_cls = ENCTYPE_TABLE[session_key.enctype]
    except (KeyError, AttributeError) as exc:
        msg = f"Failed to extract TGT from ccache: {exc}"
        raise KerbWolfError(msg) from exc

    _log.debug("TGT session key etype: %d", session_key.enctype)
    return tgt_bytes, session_key, cipher_cls

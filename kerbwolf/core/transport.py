"""TCP and UDP transport for Kerberos KDC communication.

Supports both IPv4 and IPv6.  The address family is auto-detected from
the target host string via ``socket.getaddrinfo``.

Impacket's ``sendReceive()`` only supports TCP.  We implement both
TCP and UDP so callers can choose the transport.
"""

from __future__ import annotations

import logging
import socket
import struct

from impacket.krb5.asn1 import KRB_ERROR as KRB_ERROR_ASN1
from pyasn1.codec.der import decoder

from kerbwolf.models import KDCError, TransportProtocol

_log = logging.getLogger(__name__)

_KRB_ERR_RESPONSE_TOO_BIG = 52
_KRB_ERROR_TAG = 0x7E


def send_receive(
    data: bytes,
    host: str,
    port: int = 88,
    *,
    protocol: TransportProtocol = TransportProtocol.TCP,
    timeout: float = 10.0,
) -> bytes:
    """Send a Kerberos message to a KDC and return the raw response.

    *host* may be an IPv4 address, IPv6 address, or hostname.
    When *protocol* is UDP the response is checked for
    ``KRB_ERR_RESPONSE_TOO_BIG`` (error 52) and the request is
    automatically retried over TCP per RFC 4120 section 7.2.1.

    Raises:
        KDCError: If the KDC is unreachable or the response is malformed.

    """
    if protocol == TransportProtocol.UDP:
        _log.debug("UDP → %s:%d (%d bytes)", host, port, len(data))
        response = _send_receive_udp(data, host, port, timeout)
        if _is_response_too_big(response):
            _log.info("UDP response too large, falling back to TCP")
            return _send_receive_tcp(data, host, port, timeout)
        _log.debug("UDP ← %d bytes", len(response))
        return response
    _log.debug("TCP → %s:%d (%d bytes)", host, port, len(data))
    response = _send_receive_tcp(data, host, port, timeout)
    _log.debug("TCP ← %d bytes", len(response))
    return response


def _is_response_too_big(response: bytes) -> bool:
    """Return ``True`` if *response* is a KRB_ERROR with code 52."""
    if not response or response[0] != _KRB_ERROR_TAG:
        return False
    try:
        krb_error = decoder.decode(response, asn1Spec=KRB_ERROR_ASN1())[0]
        return int(krb_error["error-code"]) == _KRB_ERR_RESPONSE_TOO_BIG
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Address family detection
# ---------------------------------------------------------------------------


def _resolve_af(host: str, port: int, sock_type: int) -> tuple[int, tuple]:
    """Resolve *host* to an address family and sockaddr.

    Returns ``(AF_INET or AF_INET6, sockaddr_tuple)``.
    """
    try:
        results = socket.getaddrinfo(host, port, socket.AF_UNSPEC, sock_type)
    except (socket.gaierror, OSError) as exc:
        msg = f"Cannot resolve {host}:{port}: {exc}"
        raise KDCError(error_code=0, message=msg) from exc
    if not results:
        msg = f"Cannot resolve {host}:{port}"
        raise KDCError(error_code=0, message=msg)
    family, _type, _proto, _canonname, sockaddr = results[0]
    return family, sockaddr


# ---------------------------------------------------------------------------
# TCP - 4-byte big-endian length prefix per RFC 4120 section 7.2.2
# ---------------------------------------------------------------------------


def _send_receive_tcp(data: bytes, host: str, port: int, timeout: float) -> bytes:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack("!I", len(data)) + data)
            length_bytes = _recv_exact(sock, 4)
            length = struct.unpack("!I", length_bytes)[0]
            return _recv_exact(sock, length)
    except (OSError, TimeoutError) as exc:
        msg = f"TCP connection to {host}:{port} failed: {exc}"
        raise KDCError(error_code=0, message=msg) from exc


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            msg = f"Connection closed after {len(buf)}/{n} bytes"
            raise KDCError(error_code=0, message=msg)
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# UDP - no length prefix, single datagram
# ---------------------------------------------------------------------------


def _send_receive_udp(data: bytes, host: str, port: int, timeout: float) -> bytes:
    try:
        family, sockaddr = _resolve_af(host, port, socket.SOCK_DGRAM)
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(data, sockaddr)
            response, _ = sock.recvfrom(65535)
    except KDCError:
        raise
    except (OSError, TimeoutError) as exc:
        msg = f"UDP communication with {host}:{port} failed: {exc}"
        raise KDCError(error_code=0, message=msg) from exc
    else:
        return response

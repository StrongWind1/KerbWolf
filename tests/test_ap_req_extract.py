# SPDX-License-Identifier: Apache-2.0
"""Tests for Kerberos AP-REQ service-ticket extraction from pcap streams.

The AP-REQ a client sends to a service (over SMB, HTTP, LDAP or DCE-RPC)
carries the same service ticket the KDC put in the TGS-REP, so a capture of
client-to-service traffic yields Kerberoast material with no port 88 packets.
"""

import base64

from kerbwolf.core.capture import (
    AttackType,
    CapturedHash,
    TcpStream,
    _ap_reqs_in_blob,
    _drop_repeated_tickets,
    _extract_ap_req_from_stream,
)

# A real GSS-API-wrapped Kerberos AP-REQ (etype 18), with the realm, SPN and
# cipher bytes replaced by generic values.  Layout: krb5 mech OID, the AP-REQ
# TOK_ID (01 00), then the AP-REQ (application tag 0x6e) holding the ticket.
_AP_REQ_GSS = bytes.fromhex(
    "06092a864886f71201020201006e81a43081a1a003020105a10302010ea20703050020000000a36f616d306ba003020105a10d1b0b4558414d504c452e434f4da2233021a003020101a11a30181b04636966731b10686f73742e6578616d706c652e636f6da330302ea003020112a103020105a2220420aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa41b3019a003020112a2120410bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)
_TICKET_CIPHER = b"\xaa" * 32


def _tcp_stream(data: bytes) -> TcpStream:
    s = TcpStream()
    s.extend(data)
    return s


class TestApReqsInBlob:
    def test_finds_wrapped_ap_req(self):
        out = _ap_reqs_in_blob(_AP_REQ_GSS)
        assert len(out) == 1
        cipher, captured = out[0]
        assert cipher == _TICKET_CIPHER
        assert captured.attack == AttackType.AP_REQ
        assert captured.etype == 18
        assert captured.spn == "cifs/host.example.com"
        assert captured.realm == "EXAMPLE.COM"

    def test_anchor_without_valid_ap_req_is_ignored(self):
        # The anchor bytes followed by garbage must not yield a hash.
        assert _ap_reqs_in_blob(b"\x00\x01\x00\x6e\xff\xff\xff\x00") == []

    def test_no_anchor_returns_empty(self):
        assert _ap_reqs_in_blob(b"not a kerberos token at all") == []

    def test_two_ap_reqs_in_one_blob(self):
        out = _ap_reqs_in_blob(_AP_REQ_GSS + b"\x00\x00" + _AP_REQ_GSS)
        assert len(out) == 2


def _der(tag: int, body: bytes) -> bytes:
    """One DER element with a definite length."""
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    if n < 0x100:
        return bytes([tag, 0x81, n]) + body
    return bytes([tag, 0x82, n >> 8, n & 0xFF]) + body


def _ap_req(cipher: bytes) -> bytes:
    """A bare AP-REQ (no GSS-API header) whose ticket carries *cipher*."""
    realm = _der(0x1B, b"EXAMPLE.COM")
    sname = _der(0x30, _der(0xA0, _der(0x02, b"\x01")) + _der(0xA1, _der(0x30, _der(0x1B, b"ldap") + _der(0x1B, b"dc.example.com"))))
    enc_part = _der(0x30, _der(0xA0, _der(0x02, b"\x12")) + _der(0xA2, _der(0x04, cipher)))
    ticket = _der(0x61, _der(0x30, _der(0xA0, _der(0x02, b"\x05")) + _der(0xA1, realm) + _der(0xA2, sname) + _der(0xA3, enc_part)))
    authenticator = _der(0x30, _der(0xA0, _der(0x02, b"\x12")) + _der(0xA2, _der(0x04, b"\xbb" * 16)))
    body = _der(0xA0, _der(0x02, b"\x05")) + _der(0xA1, _der(0x02, b"\x0e")) + _der(0xA2, _der(0x03, b"\x00\x20\x00\x00\x00")) + _der(0xA3, ticket) + _der(0xA4, authenticator)
    return _der(0x6E, _der(0x30, body))


def _spnego_init(mech_token: bytes) -> bytes:
    """A SPNEGO NegTokenInit that offers Kerberos and carries *mech_token*."""
    krb5_oid = bytes.fromhex("06092a864886f712010202")
    neg_token_init = _der(0x30, _der(0xA0, _der(0x30, krb5_oid)) + _der(0xA2, _der(0x04, mech_token)))
    return _der(0x60, bytes.fromhex("06062b0601050502") + _der(0xA0, neg_token_init))


class TestBareApReq:
    """An AP-REQ with no GSS-API header in front of it, as Impacket's LDAP bind sends it."""

    def test_bare_ap_req_is_found(self):
        out = _ap_reqs_in_blob(_AP_REQ_GSS[13:])
        assert len(out) == 1
        assert out[0][0] == _TICKET_CIPHER

    def test_bare_ap_req_inside_spnego(self):
        cipher = b"\xcc" * 48
        out = _ap_reqs_in_blob(b"\x30\x84\x00\x00\x01\x00" + _spnego_init(_ap_req(cipher)) + b"\x00\x00")
        assert len(out) == 1
        assert out[0][0] == cipher
        assert out[0][1].spn == "ldap/dc.example.com"
        assert out[0][1].realm == "EXAMPLE.COM"

    def test_long_ticket_uses_three_byte_lengths(self):
        cipher = b"\xdd" * 1200
        raw = _ap_req(cipher)
        assert raw[1] == 0x82
        out = _ap_reqs_in_blob(b"junk" + raw)
        assert [c for c, _ in out] == [cipher]

    def test_ldap_stream_with_a_bare_ap_req(self):
        cipher = b"\xee" * 64
        results = _extract_ap_req_from_stream(_tcp_stream(_spnego_init(_ap_req(cipher))), 389)
        assert len(results) == 1
        assert results[0].attack == AttackType.AP_REQ
        assert results[0].cipher_hex == cipher.hex()

    def test_first_fields_without_an_ap_req_around_them(self):
        assert _ap_reqs_in_blob(b"\x00" * 8 + bytes.fromhex("a003020105a10302010e") + b"\x00" * 8) == []
        assert _ap_reqs_in_blob(bytes.fromhex("a003020105a10302010e")) == []

    def test_wrapped_and_bare_copies_of_one_ticket_are_two_finds(self):
        out = _ap_reqs_in_blob(_AP_REQ_GSS + b"\x00" + _AP_REQ_GSS[13:])
        assert len(out) == 2


class TestExtractApReqFromStream:
    def test_smb_binary_stream(self):
        # SMB carries the token as binary; the port decides the path, 445 here.
        stream = _tcp_stream(b"\xfeSMB" + _AP_REQ_GSS)
        results = _extract_ap_req_from_stream(stream, 445)
        assert [r.spn for r in results] == ["cifs/host.example.com"]

    def test_http_negotiate_base64(self):
        b64 = base64.b64encode(_AP_REQ_GSS).decode()
        payload = f"GET /wsman HTTP/1.1\r\nAuthorization: Negotiate {b64}\r\n\r\n".encode()
        results = _extract_ap_req_from_stream(_tcp_stream(payload), 5985)
        assert [r.spn for r in results] == ["cifs/host.example.com"]

    def test_same_ticket_reported_once_per_stream(self):
        # A token that lingers in the buffer across segments is reported once.
        stream = _tcp_stream(_AP_REQ_GSS)
        first = _extract_ap_req_from_stream(stream, 445)
        second = _extract_ap_req_from_stream(stream, 445)
        assert len(first) == 1
        assert second == []

    def test_http_without_negotiate_yields_nothing(self):
        payload = b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
        assert _extract_ap_req_from_stream(_tcp_stream(payload), 80) == []


class TestDropRepeatedTickets:
    def _tgs(self, cipher_hex: str) -> CapturedHash:
        return CapturedHash(AttackType.TGS_REP, "svc", "R", "svc", 18, cipher_hex)

    def _apreq(self, cipher_hex: str) -> CapturedHash:
        return CapturedHash(AttackType.AP_REQ, "svc", "R", "svc", 18, cipher_hex)

    def test_ap_req_dropped_when_tgs_rep_present(self):
        kept = _drop_repeated_tickets([self._tgs("dead"), self._apreq("dead")])
        assert [h.attack for h in kept] == [AttackType.TGS_REP]

    def test_ap_req_kept_when_no_tgs_rep(self):
        kept = _drop_repeated_tickets([self._apreq("beef")])
        assert [h.attack for h in kept] == [AttackType.AP_REQ]

    def test_duplicate_ap_reqs_collapse_to_one(self):
        kept = _drop_repeated_tickets([self._apreq("beef"), self._apreq("beef")])
        assert len(kept) == 1

    def test_distinct_tickets_all_kept(self):
        kept = _drop_repeated_tickets([self._apreq("aa"), self._apreq("bb")])
        assert len(kept) == 2

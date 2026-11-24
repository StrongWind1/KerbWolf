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

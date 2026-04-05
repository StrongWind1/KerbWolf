"""Tests for capture module - packet extraction, Kerberos ASN.1, SNTP, and TCP reassembly."""

import struct

from kerbwolf.core.capture import (
    AttackType,
    TcpStreams,
    _extract_from_packet,
    _extract_kerberos_from_stream,
    _process_packet,
    _try_parse_asrep,
    _try_parse_asreq,
    _try_parse_sntp,
    _try_parse_tgsrep,
)

# ---------------------------------------------------------------------------
# _extract_from_packet
# ---------------------------------------------------------------------------


class TestExtractFromPacket:
    """Test the full packet extraction pipeline."""

    def _build_ethernet_ipv4_tcp(self, src_port, dst_port, payload):
        """Build an Ethernet + IPv4 + TCP packet."""
        tcp_header = struct.pack("!HH", src_port, dst_port) + b"\x00" * 8 + bytes([0x50, 0x00]) + b"\x00" * 6
        ip_payload = tcp_header + payload
        ip_header = bytes([0x45, 0x00]) + struct.pack("!H", 20 + len(ip_payload))
        ip_header += b"\x00" * 5 + bytes([6]) + b"\x00" * 10  # proto=TCP
        eth_header = b"\x00" * 12 + b"\x08\x00"  # Ethernet IPv4
        return eth_header + ip_header + ip_payload

    def test_non_kerberos_port_skipped(self):
        pkt = self._build_ethernet_ipv4_tcp(12345, 443, b"https data")
        assert _extract_from_packet(pkt, 1) == []

    def test_kerberos_dst_port_accepted(self):
        # We can't easily build valid ASN.1 here, but verify the port check works
        pkt = self._build_ethernet_ipv4_tcp(12345, 88, b"\x00" * 20)
        # Should return empty (invalid ASN.1) but not crash
        assert _extract_from_packet(pkt, 1) == []

    def test_kerberos_src_port_accepted(self):
        # Response from KDC (src=88)
        pkt = self._build_ethernet_ipv4_tcp(88, 54321, b"\x00" * 20)
        assert _extract_from_packet(pkt, 1) == []

    def test_tcp_length_prefix_stripped(self):
        """TCP Kerberos messages have a 4-byte length prefix."""
        # Build a packet with the 4-byte prefix
        inner = b"\x00" * 16
        prefix = struct.pack("!I", len(inner))
        pkt = self._build_ethernet_ipv4_tcp(12345, 88, prefix + inner)
        # Should not crash even with invalid ASN.1
        assert _extract_from_packet(pkt, 1) == []


# ---------------------------------------------------------------------------
# _try_parse_asreq - invalid/garbage data
# ---------------------------------------------------------------------------


class TestTryParseAsreq:
    def test_garbage_returns_empty(self):
        assert _try_parse_asreq(b"\x00\x01\x02\x03") == []

    def test_empty_returns_empty(self):
        assert _try_parse_asreq(b"") == []

    def test_truncated_returns_empty(self):
        # Something that starts like ASN.1 but is truncated
        assert _try_parse_asreq(b"\x6a\x03\x02\x01") == []


# ---------------------------------------------------------------------------
# _try_parse_asrep - invalid/garbage data
# ---------------------------------------------------------------------------


class TestTryParseAsrep:
    def test_garbage_returns_empty(self):
        assert _try_parse_asrep(b"\xff\xfe\xfd") == []

    def test_empty_returns_empty(self):
        assert _try_parse_asrep(b"") == []


# ---------------------------------------------------------------------------
# _try_parse_tgsrep - invalid/garbage data
# ---------------------------------------------------------------------------


class TestTryParseTgsrep:
    def test_garbage_returns_empty(self):
        assert _try_parse_tgsrep(b"\x00" * 50) == []

    def test_empty_returns_empty(self):
        assert _try_parse_tgsrep(b"") == []


# ---------------------------------------------------------------------------
# IPv6 packet handling
# ---------------------------------------------------------------------------


class TestIPv6Packets:
    def test_ipv6_tcp_packet(self):
        """IPv6 + TCP packet on port 88 should be accepted."""
        # IPv6 header: version=6, next_header=6 (TCP), hop_limit=64
        tcp_header = struct.pack("!HH", 12345, 88) + b"\x00" * 8 + bytes([0x50, 0x00]) + b"\x00" * 6
        ipv6_header = bytes([0x60, 0x00, 0x00, 0x00])  # version 6
        ipv6_header += struct.pack("!H", len(tcp_header))  # payload length
        ipv6_header += bytes([6, 64])  # next_header=TCP, hop_limit
        ipv6_header += b"\x00" * 32  # src + dst addresses

        eth = b"\x00" * 12 + b"\x86\xdd"  # Ethernet IPv6
        pkt = eth + ipv6_header + tcp_header + b"\x00" * 10

        # Should not crash, even with garbage payload
        result = _extract_from_packet(pkt, 1)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# UDP packet handling
# ---------------------------------------------------------------------------


class TestUDPPackets:
    def test_udp_kerberos_packet(self):
        """UDP on port 88 should also be accepted."""
        udp_header = struct.pack("!HHHH", 54321, 88, 28, 0)
        payload = b"\x00" * 20
        ip_header = bytes([0x45, 0x00]) + struct.pack("!H", 20 + 8 + len(payload))
        ip_header += b"\x00" * 5 + bytes([17]) + b"\x00" * 10  # proto=UDP

        eth = b"\x00" * 12 + b"\x08\x00"
        pkt = eth + ip_header + udp_header + payload

        result = _extract_from_packet(pkt, 1)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# _try_parse_sntp - MS-SNTP response parsing
# ---------------------------------------------------------------------------


class TestTryParseSntp:
    """Test MS-SNTP response extraction from raw NTP payloads."""

    def test_68_byte_response(self):
        """Valid 68-byte Authenticator response produces SNTP_MD5 hash."""
        salt = b"\x23\x02\x0a" + b"\x00" * 45  # 48-byte NTP header
        rid = 1000
        key_id = struct.pack("<I", rid)
        checksum = b"\xaa" * 16
        payload = salt + key_id + checksum
        assert len(payload) == 68

        result = _try_parse_sntp(payload)
        assert len(result) == 1
        h = result[0]
        assert h.attack == AttackType.SNTP_MD5
        assert h.rid == 1000
        assert h.username == "1000"
        assert h.cipher_hex == checksum.hex()
        assert h.salt_hex == salt.hex()

    def test_68_byte_old_pwd_bit31(self):
        """68-byte response with bit 31 set (old password) - RID still extracted correctly."""
        salt = b"\x00" * 48
        rid = 1500
        key_id = struct.pack("<I", rid | (1 << 31))  # bit 31 set
        checksum = b"\xbb" * 16
        payload = salt + key_id + checksum

        result = _try_parse_sntp(payload)
        assert len(result) == 1
        assert result[0].rid == 1500  # bit 31 masked out

    def test_68_byte_request_filtered(self):
        """68-byte request (all-zero checksum) is filtered out."""
        payload = b"\x00" * 48 + struct.pack("<I", 1000) + b"\x00" * 16
        assert _try_parse_sntp(payload) == []

    def test_120_byte_response(self):
        """Valid 120-byte ExtendedAuthenticator response produces SNTP_SHA512 hash."""
        salt = b"\x23\x02\x0a" + b"\x00" * 45
        rid = 2000
        key_id = struct.pack("<I", rid)
        control = b"\x00\x01\x00\x00"  # Reserved, Flags, Hints, SigHashID
        checksum = b"\xcc" * 64
        payload = salt + key_id + control + checksum
        assert len(payload) == 120

        result = _try_parse_sntp(payload)
        assert len(result) == 1
        h = result[0]
        assert h.attack == AttackType.SNTP_SHA512
        assert h.rid == 2000
        assert h.cipher_hex == checksum.hex()
        assert h.salt_hex == salt.hex()

    def test_120_byte_request_filtered(self):
        """120-byte request (all-zero checksum) is filtered out."""
        payload = b"\x00" * 48 + struct.pack("<I", 2000) + b"\x00" * 4 + b"\x00" * 64
        assert _try_parse_sntp(payload) == []

    def test_wrong_length_ignored(self):
        """Packets that aren't 68 or 120 bytes return empty."""
        assert _try_parse_sntp(b"\x00" * 48) == []
        assert _try_parse_sntp(b"\x00" * 100) == []
        assert _try_parse_sntp(b"") == []

    def test_regular_ntp_48_byte_ignored(self):
        """Standard 48-byte NTP packets are not MS-SNTP."""
        assert _try_parse_sntp(b"\x23\x02\x0a" + b"\x00" * 45) == []


# ---------------------------------------------------------------------------
# SNTP full packet extraction (Ethernet + IP + UDP + NTP)
# ---------------------------------------------------------------------------


class TestSntpPacketExtraction:
    """Test SNTP extraction through the full packet pipeline."""

    def _build_ethernet_ipv4_udp(self, src_port, dst_port, payload):
        """Build an Ethernet + IPv4 + UDP packet."""
        udp_len = 8 + len(payload)
        udp_header = struct.pack("!HHH", src_port, dst_port, udp_len) + b"\x00\x00"
        ip_payload = udp_header + payload
        ip_header = bytes([0x45, 0x00]) + struct.pack("!H", 20 + len(ip_payload))
        ip_header += b"\x00" * 5 + bytes([17]) + b"\x00" * 10  # proto=UDP
        eth_header = b"\x00" * 12 + b"\x08\x00"
        return eth_header + ip_header + ip_payload

    def test_ntp_dst_port_123(self):
        """UDP to port 123 with 68-byte NTP response extracts SNTP hash."""
        salt = b"\x00" * 48
        ntp_payload = salt + struct.pack("<I", 1000) + b"\xdd" * 16
        pkt = self._build_ethernet_ipv4_udp(54321, 123, ntp_payload)
        result = _extract_from_packet(pkt, 1)
        assert len(result) == 1
        assert result[0].attack == AttackType.SNTP_MD5

    def test_ntp_src_port_123(self):
        """UDP from port 123 (DC response) extracts SNTP hash."""
        salt = b"\x00" * 48
        ntp_payload = salt + struct.pack("<I", 1000) + b"\xee" * 16
        pkt = self._build_ethernet_ipv4_udp(123, 54321, ntp_payload)
        result = _extract_from_packet(pkt, 1)
        assert len(result) == 1
        assert result[0].attack == AttackType.SNTP_MD5

    def test_ntp_120_byte_extraction(self):
        """120-byte SNTP response through full pipeline."""
        salt = b"\x00" * 48
        ntp_payload = salt + struct.pack("<I", 2000) + b"\x00" * 4 + b"\xff" * 64
        pkt = self._build_ethernet_ipv4_udp(123, 54321, ntp_payload)
        result = _extract_from_packet(pkt, 1)
        assert len(result) == 1
        assert result[0].attack == AttackType.SNTP_SHA512

    def test_ntp_request_not_extracted(self):
        """NTP request (zero checksum) on port 123 is not extracted."""
        ntp_payload = b"\x00" * 68  # all zeros = request
        pkt = self._build_ethernet_ipv4_udp(54321, 123, ntp_payload)
        assert _extract_from_packet(pkt, 1) == []

    def test_non_ntp_port_skipped(self):
        """UDP on a non-NTP port with 68 bytes is not parsed as SNTP."""
        ntp_payload = b"\x00" * 48 + struct.pack("<I", 1000) + b"\xaa" * 16
        pkt = self._build_ethernet_ipv4_udp(54321, 999, ntp_payload)
        assert _extract_from_packet(pkt, 1) == []


# ---------------------------------------------------------------------------
# TCP stream reassembly: _extract_kerberos_from_stream
# ---------------------------------------------------------------------------


class TestKerberosStreamExtraction:
    """Test length-prefix-aware Kerberos extraction from TCP stream buffers."""

    def test_complete_message(self):
        """Single complete message in buffer is extracted and consumed."""
        krb_data = b"\x00" * 20  # Fake Kerberos (won't parse, but tests consumption)
        length_prefix = struct.pack("!I", len(krb_data))
        buf = bytearray(length_prefix + krb_data)
        _extract_kerberos_from_stream(buf)
        assert len(buf) == 0  # Buffer consumed

    def test_incomplete_message_stays_in_buffer(self):
        """Incomplete message stays in the buffer."""
        length_prefix = struct.pack("!I", 200)  # Claims 200 bytes
        partial = b"\x00" * 50  # Only 50 bytes of payload
        buf = bytearray(length_prefix + partial)
        _extract_kerberos_from_stream(buf)
        assert len(buf) == 54  # 4 prefix + 50 partial, unchanged

    def test_split_message_assembled(self):
        """Two segments combine to form a complete message."""
        krb_data = b"\x00" * 100
        length_prefix = struct.pack("!I", len(krb_data))
        full = length_prefix + krb_data

        buf = bytearray(full[:60])  # First segment: 60 bytes
        _extract_kerberos_from_stream(buf)
        assert len(buf) == 60  # Not enough data yet

        buf.extend(full[60:])  # Second segment: remaining
        _extract_kerberos_from_stream(buf)
        assert len(buf) == 0  # Now complete, consumed

    def test_multiple_messages(self):
        """Multiple complete messages back-to-back."""
        msg1 = struct.pack("!I", 10) + b"\x00" * 10
        msg2 = struct.pack("!I", 20) + b"\x00" * 20
        buf = bytearray(msg1 + msg2)
        _extract_kerberos_from_stream(buf)
        assert len(buf) == 0  # Both consumed

    def test_empty_buffer(self):
        buf = bytearray()
        _extract_kerberos_from_stream(buf)
        assert len(buf) == 0


# ---------------------------------------------------------------------------
# TCP reassembly through full packet pipeline
# ---------------------------------------------------------------------------


class TestTcpReassemblyPipeline:
    """Test TCP reassembly through _process_packet."""

    def _build_ethernet_ipv4_tcp(self, src_ip_bytes, src_port, dst_ip_bytes, dst_port, payload, *, syn=False):
        """Build Ethernet + IPv4 + TCP packet."""
        flags_byte = 0x02 if syn else 0x10  # SYN or ACK
        tcp_header = struct.pack("!HH", src_port, dst_port) + b"\x00" * 8
        tcp_header += bytes([0x50, flags_byte]) + b"\x00" * 6  # data_offset=5, flags
        ip_payload = tcp_header + payload
        ip_header = bytes([0x45, 0x00]) + struct.pack("!H", 20 + len(ip_payload))
        ip_header += b"\x00" * 5 + bytes([6])  # proto=TCP
        ip_header += b"\x00" * 2 + src_ip_bytes + dst_ip_bytes
        eth_header = b"\x00" * 12 + b"\x08\x00"
        return eth_header + ip_header + ip_payload

    def test_split_kerberos_tcp_message(self):
        """Kerberos message split across two TCP segments is reassembled."""
        # Build a "Kerberos" message with length prefix (won't parse as real ASN.1).
        krb_data = b"\x6a" + b"\x00" * 99  # 100 bytes, starts with ASN.1-ish byte
        full_msg = struct.pack("!I", len(krb_data)) + krb_data

        src = b"\x0a\x00\x00\x01"
        dst = b"\x0a\x00\x00\x02"
        tcp_streams: TcpStreams = {}
        ntlm_sessions: dict[tuple[str, int, str, int], bytes] = {}

        # Segment 1: first 60 bytes (length prefix + 56 bytes of data)
        pkt1 = self._build_ethernet_ipv4_tcp(src, 12345, dst, 88, full_msg[:60])
        results1 = _process_packet(pkt1, 1, tcp_streams, ntlm_sessions)
        assert results1 == []  # Incomplete, no extraction yet
        assert len(tcp_streams) == 1  # Buffer exists

        # Segment 2: remaining bytes
        pkt2 = self._build_ethernet_ipv4_tcp(src, 12345, dst, 88, full_msg[60:])
        _process_packet(pkt2, 1, tcp_streams, ntlm_sessions)
        # Buffer should be consumed (message was complete, even if ASN.1 parsing fails)
        assert len(tcp_streams) == 0 or len(next(iter(tcp_streams.values()))) == 0

    def test_syn_resets_buffer(self):
        """TCP SYN flag clears any existing buffer for the connection."""
        src = b"\x0a\x00\x00\x01"
        dst = b"\x0a\x00\x00\x02"
        tcp_streams: TcpStreams = {}
        ntlm_sessions: dict[tuple[str, int, str, int], bytes] = {}

        # First packet: partial data
        pkt1 = self._build_ethernet_ipv4_tcp(src, 12345, dst, 88, b"\x00" * 50)
        _process_packet(pkt1, 1, tcp_streams, ntlm_sessions)
        assert len(tcp_streams) == 1

        # SYN packet: should reset buffer
        pkt_syn = self._build_ethernet_ipv4_tcp(src, 12345, dst, 88, b"", syn=True)
        _process_packet(pkt_syn, 1, tcp_streams, ntlm_sessions)
        # Buffer should be cleared (SYN with empty payload)
        key = ("10.0.0.1", 12345, "10.0.0.2", 88)
        assert key not in tcp_streams or len(tcp_streams[key]) == 0

    def test_udp_sntp_still_works(self):
        """UDP SNTP extraction is unaffected by TCP reassembly changes."""
        salt = b"\x00" * 48
        ntp_payload = salt + struct.pack("<I", 1000) + b"\xdd" * 16  # 68 bytes
        udp_header = struct.pack("!HHH", 54321, 123, 8 + len(ntp_payload)) + b"\x00\x00"
        ip_payload = udp_header + ntp_payload
        ip_header = bytes([0x45, 0x00]) + struct.pack("!H", 20 + len(ip_payload))
        ip_header += b"\x00" * 5 + bytes([17]) + b"\x00" * 10  # proto=UDP
        eth_header = b"\x00" * 12 + b"\x08\x00"
        pkt = eth_header + ip_header + ip_payload

        tcp_streams: TcpStreams = {}
        ntlm_sessions: dict[tuple[str, int, str, int], bytes] = {}
        results = _process_packet(pkt, 1, tcp_streams, ntlm_sessions)
        assert len(results) == 1
        assert results[0].attack == AttackType.SNTP_MD5

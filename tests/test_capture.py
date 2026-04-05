"""Tests for kerbwolf.core.capture - native pcap/pcapng parsing and Kerberos extraction."""

import struct

import pytest

from kerbwolf.core.capture import (
    AttackType,
    CapturedHash,
    _skip_ipv6_extensions,
    _strip_ip_transport,
    _strip_link_layer,
    parse_pcap,
)
from kerbwolf.models import KerbWolfError

# ---------------------------------------------------------------------------
# AttackType enum
# ---------------------------------------------------------------------------


class TestAttackType:
    def test_asreq_value(self):
        assert AttackType.AS_REQ == "AS-REQ"

    def test_asrep_value(self):
        assert AttackType.AS_REP == "AS-REP"

    def test_tgsrep_value(self):
        assert AttackType.TGS_REP == "TGS-REP"

    def test_sntp_md5_value(self):
        assert AttackType.SNTP_MD5 == "SNTP-MD5"

    def test_sntp_sha512_value(self):
        assert AttackType.SNTP_SHA512 == "SNTP-SHA512"


# ---------------------------------------------------------------------------
# CapturedHash dataclass
# ---------------------------------------------------------------------------


class TestCapturedHash:
    def test_creation(self):
        h = CapturedHash(attack=AttackType.AS_REQ, username="u", realm="R", spn="krbtgt/R", etype=23, cipher_hex="aabb")
        assert h.attack == AttackType.AS_REQ
        assert h.cipher_hex == "aabb"

    def test_frozen(self):
        h = CapturedHash(attack=AttackType.AS_REP, username="u", realm="R", spn="s", etype=1, cipher_hex="ff")
        with pytest.raises(AttributeError):
            h.username = "changed"

    def test_sntp_defaults(self):
        h = CapturedHash(attack=AttackType.AS_REQ, username="u", realm="R", spn="s", etype=23, cipher_hex="aa")
        assert h.salt_hex == ""
        assert h.rid == 0

    def test_sntp_fields(self):
        h = CapturedHash(
            attack=AttackType.SNTP_MD5,
            username="1000",
            realm="",
            spn="",
            etype=0,
            cipher_hex="aa" * 16,
            salt_hex="bb" * 48,
            rid=1000,
        )
        assert h.rid == 1000
        assert len(h.salt_hex) == 96


# ---------------------------------------------------------------------------
# Link layer stripping
# ---------------------------------------------------------------------------


class TestStripLinkLayer:
    def test_ethernet_ipv4(self):
        # 6 bytes dst + 6 bytes src + 2 bytes ethertype (0x0800) + payload
        pkt = b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 19
        result = _strip_link_layer(pkt, 1)
        assert result is not None
        assert result[0] == 0x45  # IPv4 version nibble

    def test_ethernet_ipv6(self):
        pkt = b"\x00" * 12 + b"\x86\xdd" + b"\x60" + b"\x00" * 39
        result = _strip_link_layer(pkt, 1)
        assert result is not None
        assert result[0] == 0x60

    def test_ethernet_not_ip(self):
        pkt = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 20  # ARP
        result = _strip_link_layer(pkt, 1)
        assert result is None

    def test_ethernet_vlan_tagged(self):
        # 802.1Q VLAN: ethertype 0x8100, then 2 bytes VLAN tag, then real ethertype
        pkt = b"\x00" * 12 + b"\x81\x00" + b"\x00\x01" + b"\x08\x00" + b"\x45" + b"\x00" * 19
        result = _strip_link_layer(pkt, 1)
        assert result is not None
        assert result[0] == 0x45

    def test_raw_linktype(self):
        pkt = b"\x45" + b"\x00" * 19
        result = _strip_link_layer(pkt, 101)
        assert result == pkt

    def test_linux_sll(self):
        pkt = b"\x00" * 16 + b"\x45" + b"\x00" * 19
        result = _strip_link_layer(pkt, 113)
        assert result is not None
        assert result[0] == 0x45

    def test_linux_sll2(self):
        pkt = b"\x00" * 20 + b"\x45" + b"\x00" * 19
        result = _strip_link_layer(pkt, 276)
        assert result is not None

    def test_unknown_linktype(self):
        result = _strip_link_layer(b"\x00" * 30, 999)
        assert result is None

    def test_too_short_ethernet(self):
        result = _strip_link_layer(b"\x00" * 10, 1)
        assert result is None


# ---------------------------------------------------------------------------
# IP + Transport stripping
# ---------------------------------------------------------------------------


class TestStripIpTransport:
    def _build_ipv4_tcp(self, src_port, dst_port, payload):
        """Build a minimal IPv4 + TCP packet."""
        tcp_header = struct.pack("!HH", src_port, dst_port) + b"\x00" * 8 + bytes([0x50, 0x00]) + b"\x00" * 6
        # IP header: version=4, ihl=5 (20 bytes), total length, protocol=6 (TCP)
        ip_header = bytes([0x45, 0x00]) + struct.pack("!H", 20 + len(tcp_header) + len(payload))
        ip_header += b"\x00" * 5 + bytes([6]) + b"\x00" * 10  # protocol=6 at offset 9
        return ip_header + tcp_header + payload

    def _build_ipv4_udp(self, src_port, dst_port, payload):
        """Build a minimal IPv4 + UDP packet."""
        udp_header = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
        ip_header = bytes([0x45, 0x00]) + struct.pack("!H", 20 + len(udp_header) + len(payload))
        ip_header += b"\x00" * 5 + bytes([17]) + b"\x00" * 10  # protocol=17
        return ip_header + udp_header + payload

    def test_ipv4_tcp_ports(self):
        pkt = self._build_ipv4_tcp(12345, 88, b"kerberos_data")
        _payload, src, dst, proto = _strip_ip_transport(pkt)
        assert src == 12345
        assert dst == 88
        assert proto == 6

    def test_ipv4_udp_ports(self):
        pkt = self._build_ipv4_udp(54321, 88, b"kerberos_data")
        _payload, src, dst, proto = _strip_ip_transport(pkt)
        assert src == 54321
        assert dst == 88
        assert proto == 17

    def test_too_short(self):
        payload, _src, _dst, _proto = _strip_ip_transport(b"\x00" * 10)
        assert payload is None

    def test_invalid_version(self):
        pkt = bytes([0x30]) + b"\x00" * 39  # version 3
        payload, _, _, _ = _strip_ip_transport(pkt)
        assert payload is None


# ---------------------------------------------------------------------------
# pcap format detection
# ---------------------------------------------------------------------------


class TestParsePcap:
    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.pcap"
        f.write_bytes(b"")
        assert parse_pcap(str(f)) == []

    def test_truncated_header(self, tmp_path):
        f = tmp_path / "short.pcap"
        f.write_bytes(b"\xd4\xc3")
        assert parse_pcap(str(f)) == []

    def test_unknown_magic(self, tmp_path):
        f = tmp_path / "bad.pcap"
        f.write_bytes(b"\x00\x00\x00\x00")
        with pytest.raises(KerbWolfError, match="Unknown file format"):
            parse_pcap(str(f))

    def test_valid_pcap_no_packets(self, tmp_path):
        # Valid pcap header (little-endian), no packet records.
        header = struct.pack("<I HH i I I I", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        f = tmp_path / "empty_valid.pcap"
        f.write_bytes(header)
        assert parse_pcap(str(f)) == []

    def test_valid_pcap_big_endian_no_packets(self, tmp_path):
        header = struct.pack(">I HH i I I I", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        f = tmp_path / "be.pcap"
        f.write_bytes(header)
        assert parse_pcap(str(f)) == []

    def test_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            parse_pcap("/nonexistent/file.pcap")


# ---------------------------------------------------------------------------
# pcapng format
# ---------------------------------------------------------------------------


class TestParsePcapng:
    def test_minimal_pcapng_no_packets(self, tmp_path):
        bo_magic = struct.pack("<I", 0x1A2B3C4D)
        shb_body = bo_magic + struct.pack("<HH q", 1, 0, -1)  # version 1.0, section length -1
        shb_len = 12 + len(shb_body)  # type(4) + len(4) + body + trailing_len(4)
        shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)

        f = tmp_path / "minimal.pcapng"
        f.write_bytes(shb)
        assert parse_pcap(str(f)) == []


# ---------------------------------------------------------------------------
# IPv6 extension header chain walking
# ---------------------------------------------------------------------------


class TestSkipIpv6Extensions:
    """Test _skip_ipv6_extensions for RFC 8200 extension header traversal."""

    def test_no_extensions_tcp(self):
        """Next Header = TCP (6), no extensions -> pass through."""
        proto, data = _skip_ipv6_extensions(6, b"\x00" * 40)
        assert proto == 6
        assert data == b"\x00" * 40

    def test_no_extensions_udp(self):
        """Next Header = UDP (17), no extensions -> pass through."""
        proto, _data = _skip_ipv6_extensions(17, b"\xff" * 20)
        assert proto == 17

    def test_hop_by_hop_then_tcp(self):
        """Hop-by-Hop (type 0) -> TCP.  Header ext len = 0 means 8 bytes total."""
        hop = bytes([6, 0]) + b"\x00" * 6
        tcp_payload = b"\xaa" * 30
        proto, data = _skip_ipv6_extensions(0, hop + tcp_payload)
        assert proto == 6
        assert data == tcp_payload

    def test_routing_then_udp(self):
        """Routing header (type 43) -> UDP."""
        routing = bytes([17, 1]) + b"\x00" * 14
        udp_payload = b"\xbb" * 20
        proto, data = _skip_ipv6_extensions(43, routing + udp_payload)
        assert proto == 17
        assert data == udp_payload

    def test_fragment_then_tcp(self):
        """Fragment header (type 44) is always 8 bytes."""
        frag = bytes([6, 0, 0, 0, 0, 0, 0, 0])
        tcp_payload = b"\xcc" * 20
        proto, data = _skip_ipv6_extensions(44, frag + tcp_payload)
        assert proto == 6
        assert data == tcp_payload

    def test_destination_options_then_tcp(self):
        """Destination Options (type 60) -> TCP."""
        dest = bytes([6, 0]) + b"\x00" * 6
        tcp_payload = b"\xdd" * 20
        proto, data = _skip_ipv6_extensions(60, dest + tcp_payload)
        assert proto == 6
        assert data == tcp_payload

    def test_chained_hop_routing_tcp(self):
        """Hop-by-Hop -> Routing -> TCP (two extensions in chain)."""
        hop = bytes([43, 0]) + b"\x00" * 6
        routing = bytes([6, 0]) + b"\x00" * 6
        tcp_payload = b"\xee" * 20
        proto, data = _skip_ipv6_extensions(0, hop + routing + tcp_payload)
        assert proto == 6
        assert data == tcp_payload

    def test_empty_data(self):
        proto, data = _skip_ipv6_extensions(0, b"")
        assert proto == 0
        assert data == b""

    def test_truncated_extension(self):
        proto, data = _skip_ipv6_extensions(0, b"\x06")
        assert proto == 0
        assert data == b"\x06"


class TestIpv6ExtensionIntegration:
    """Test _strip_ip_transport with IPv6 extension headers in full packets."""

    def test_ipv6_hop_by_hop_tcp_port_88(self):
        """IPv6 with Hop-by-Hop -> TCP port 88."""
        hop = bytes([6, 0]) + b"\x00" * 6
        tcp_header = struct.pack("!HH", 12345, 88) + b"\x00" * 8 + bytes([0x50, 0x00]) + b"\x00" * 6
        ipv6 = bytes([0x60, 0x00, 0x00, 0x00])
        ipv6 += struct.pack("!H", len(hop) + len(tcp_header))
        ipv6 += bytes([0, 64])  # Next Header = Hop-by-Hop (0)
        ipv6 += b"\x00" * 32
        ipv6 += hop + tcp_header

        _payload, _src_port, dst_port, proto = _strip_ip_transport(ipv6)
        assert proto == 6
        assert dst_port == 88

    def test_ipv6_fragment_udp_port_123(self):
        """IPv6 with Fragment header -> UDP port 123."""
        frag = bytes([17, 0, 0, 0, 0, 0, 0, 0])
        udp_payload = b"\x00" * 68
        udp_header = struct.pack("!HHH", 54321, 123, 8 + len(udp_payload)) + b"\x00\x00"
        ipv6 = bytes([0x60, 0x00, 0x00, 0x00])
        ipv6 += struct.pack("!H", len(frag) + len(udp_header) + len(udp_payload))
        ipv6 += bytes([44, 64])  # Next Header = Fragment (44)
        ipv6 += b"\x00" * 32
        ipv6 += frag + udp_header + udp_payload

        _payload, _src_port, dst_port, proto = _strip_ip_transport(ipv6)
        assert proto == 17
        assert dst_port == 123

    def test_ipv6_no_extension_still_works(self):
        """IPv6 with no extensions (Next Header = TCP directly)."""
        tcp_header = struct.pack("!HH", 54321, 445) + b"\x00" * 8 + bytes([0x50, 0x00]) + b"\x00" * 6
        ipv6 = bytes([0x60, 0x00, 0x00, 0x00])
        ipv6 += struct.pack("!H", len(tcp_header))
        ipv6 += bytes([6, 64])  # Next Header = TCP (6) directly
        ipv6 += b"\x00" * 32
        ipv6 += tcp_header

        _payload, _src_port, dst_port, proto = _strip_ip_transport(ipv6)
        assert proto == 6
        assert dst_port == 445

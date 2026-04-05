"""Tests using real NTP traffic captured from /root/ntp.pcapng.

The capture contains 120-byte ExtendedAuthenticator packets between a
Windows NTP client (10.252.0.15) and a DC (10.252.0.12) for RID 1103
(WIN10-CLIENT$).  The requests use Flags=0x01 (USE_OLDKEY_VERSION) and
ClientHints=0x00 (no HMAC-SHA512), so the DC responds with MD5-based
MACs in 120-byte format.

These tests validate:
1. Our packet parser handles both 68-byte and 120-byte formats
2. Field extraction matches what tshark shows
3. Our 68-byte request builder produces valid packets
4. Hash format output matches hashcat mode 31300
"""

import struct

from kerbwolf.core.ntp import (
    build_request,
    parse_response,
)
from kerbwolf.hashcat import format_sntp_hash

# ---------------------------------------------------------------------------
# Raw packets from /root/ntp.pcapng (NTP payload only, no Ethernet/IP/UDP)
# ---------------------------------------------------------------------------

# Packet 1: ExtendedAuthenticator request, RID=1103, Flags=0x01 (USE_OLDKEY)
PCAP_REQ_1 = bytes.fromhex(
    "db000ae9000002ac00019b8500000000"
    "ed6c737f3059beb8000000000000000000000000"
    "00000000ed6c7ea32451b930"
    "4f040000"  # Key ID: 0x0000044f = RID 1103, no bit-31 (ExtendedAuth uses Flags instead)
    "00"  # Reserved
    "01"  # Flags: USE_OLDKEY_VERSION
    "00"  # ClientHashIDHints: 0 (no HMAC-SHA512)
    "00" + "00" * 64  # SignatureHashID: 0  # Crypto-Checksum: 64 zero bytes
)

# Packet 2: ExtendedAuthenticator response from DC
PCAP_RESP_2 = bytes.fromhex(
    "1c020ae90000036a00000beed8ef230c"
    "ed6c7c0175f9a7f7ed6c7ea32451b930"
    "ed6c7ea302019e65ed6c7ea3021b1605"
    "4f040000"  # Key ID echoed
    "01"  # Reserved (server sets to 1 per product behavior)
    "00"  # Flags
    "00"  # ClientHashIDHints
    "00"  # SignatureHashID: 0 (MD5 fallback, not HMAC-SHA512)
    "a9eacddef103c3a366fc28acb2519c1e"  # First 16 bytes = MD5 MAC
    "62000a2aefc3e76bbe4eaba65050c7b5"
    "f80ba9f41de4390859bdd9e6b5c53f9b"
    "b7cd4ab54993b5baed9fb2def1d8e41d"
)

# Packet 4: second response (different salt/timestamps, same RID)
PCAP_RESP_4 = bytes.fromhex("1c0211e90000036a00000bf5d8ef230ced6c7c017692c640ed6c7eac78eb554eed6c7eac56928d35ed6c7eac56b18e824f04000001000000239609a50e36c12d8fd20fd512543e31c602370db3836f2059ba047ee8fc72a6825e736a6fd8f5b63c14bea389bbafa9291026a05e14d1354bad19d5eabd9257")


# ---------------------------------------------------------------------------
# Validate pcap packet structure
# ---------------------------------------------------------------------------


class TestPcapPacketStructure:
    def test_request_is_120_bytes(self):
        assert len(PCAP_REQ_1) == 120

    def test_response_is_120_bytes(self):
        assert len(PCAP_RESP_2) == 120

    def test_request_mode_is_client(self):
        assert PCAP_REQ_1[0] & 0x7 == 3  # Mode=3 (client)

    def test_response_mode_is_server(self):
        assert PCAP_RESP_2[0] & 0x7 == 4  # Mode=4 (server)

    def test_request_key_id_is_rid_1103(self):
        key_id = struct.unpack("<I", PCAP_REQ_1[48:52])[0]
        assert key_id == 1103

    def test_response_key_id_echoed(self):
        req_key = struct.unpack("<I", PCAP_REQ_1[48:52])[0]
        resp_key = struct.unpack("<I", PCAP_RESP_2[48:52])[0]
        assert req_key == resp_key

    def test_request_flags_use_oldkey(self):
        assert PCAP_REQ_1[53] == 0x01  # USE_OLDKEY_VERSION

    def test_request_client_hints_no_hmac(self):
        assert PCAP_REQ_1[54] == 0x00  # No HMAC-SHA512

    def test_response_sig_hash_id_md5(self):
        assert PCAP_RESP_2[55] == 0x00  # MD5 fallback

    def test_request_checksum_all_zeros(self):
        assert all(b == 0 for b in PCAP_REQ_1[56:120])

    def test_response_checksum_not_zeros(self):
        assert not all(b == 0 for b in PCAP_RESP_2[56:120])

    def test_response_md5_is_first_16_of_checksum(self):
        md5_mac = PCAP_RESP_2[56:72]
        assert md5_mac == bytes.fromhex("a9eacddef103c3a366fc28acb2519c1e")

    def test_different_responses_have_different_salts(self):
        salt_2 = PCAP_RESP_2[:48]
        salt_4 = PCAP_RESP_4[:48]
        assert salt_2 != salt_4

    def test_different_responses_have_different_checksums(self):
        checksum_2 = PCAP_RESP_2[56:72]
        checksum_4 = PCAP_RESP_4[56:72]
        assert checksum_2 != checksum_4


# ---------------------------------------------------------------------------
# Validate our 68-byte request builder against pcap data
# ---------------------------------------------------------------------------


class TestOurRequestVsPcap:
    def test_our_request_is_68_bytes(self):
        pkt = build_request(1103)
        assert len(pkt) == 68

    def test_our_request_same_rid_encoding(self):
        """Our 68-byte Key ID should encode the same RID as the 120-byte capture."""
        our_pkt = build_request(1103)
        our_key_id = struct.unpack("<I", our_pkt[48:52])[0]
        pcap_key_id = struct.unpack("<I", PCAP_REQ_1[48:52])[0]
        assert our_key_id == pcap_key_id == 1103

    def test_our_request_mode_is_client(self):
        pkt = build_request(1103)
        assert pkt[0] & 0x7 == 3  # Mode=3

    def test_our_checksum_is_zeros(self):
        pkt = build_request(1103)
        assert pkt[52:68] == b"\x00" * 16

    def test_our_old_pwd_uses_bit31_not_flags(self):
        """68-byte Authenticator uses bit 31 in Key ID, not the Flags byte."""
        pkt = build_request(1103, old_pwd=True)
        key_id = struct.unpack("<I", pkt[48:52])[0]
        assert key_id & (1 << 31) != 0  # Bit 31 set
        assert key_id & ((1 << 31) - 1) == 1103  # RID preserved


# ---------------------------------------------------------------------------
# Validate our response parser with 68-byte simulated responses
# ---------------------------------------------------------------------------


class TestParseResponseFromPcapData:
    def test_parse_68byte_simulated_from_pcap_salt(self):
        """Build a 68-byte response using the pcap's salt and MD5, verify parsing."""
        salt = PCAP_RESP_2[:48]
        md5_mac = PCAP_RESP_2[56:72]  # First 16 bytes of 64-byte checksum
        key_id = struct.pack("<I", 1103)

        simulated_68 = salt + key_id + md5_mac
        assert len(simulated_68) == 68

        result = parse_response(simulated_68)
        assert result is not None
        assert result.rid == 1103
        assert result.md5_hash == md5_mac
        assert result.salt == salt
        assert not result.is_extended

    def test_120byte_response_parsed_as_extended(self):
        """120-byte packets are always SHA512 regardless of SigHashID."""
        result = parse_response(PCAP_RESP_2)
        assert result is not None
        assert result.is_extended
        assert result.rid == 1103
        assert result.sig_hash_id == 0x00  # DC bug: should be 0x01 per spec
        assert result.is_sha512  # always SHA512 for 120-byte

    def test_120byte_checksum_first_16(self):
        result = parse_response(PCAP_RESP_2)
        assert result.checksum[:16] == bytes.fromhex("a9eacddef103c3a366fc28acb2519c1e")


# ---------------------------------------------------------------------------
# Validate hash formatting with pcap-derived data
# ---------------------------------------------------------------------------


class TestHashFormatFromPcap:
    def test_format_matches_hashcat_31300(self):
        salt = PCAP_RESP_2[:48]
        md5_mac = PCAP_RESP_2[56:72]
        h = format_sntp_hash(md5_mac, salt, 1103)

        assert h.startswith("$sntp-ms$")
        parts = h.split("$")
        assert parts[2] == "1103"  # RID
        assert len(parts[3]) == 32  # MD5 digest
        assert len(parts[4]) == 96  # salt
        assert parts[3] == "a9eacddef103c3a366fc28acb2519c1e"
        assert parts[4] == salt.hex()

    def test_format_with_rid_in_hash(self):
        salt = PCAP_RESP_2[:48]
        md5_mac = PCAP_RESP_2[56:72]
        h = format_sntp_hash(md5_mac, salt, 1103)
        assert "$sntp-ms$1103$" in h

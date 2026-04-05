"""Tests for kerbwolf.core.ntp: MS-SNTP packet construction, parsing, and crypto."""

import struct

from kerbwolf.core.ntp import (
    _AUTH_LEN,
    _EXT_AUTH_LEN,
    _KEY_SELECTOR_OLD,
    _NTP_CLIENT_HEADER,
    _NTP_HEADER_LEN,
    build_extended_request,
    build_request,
    compute_extended_checksum,
    kdf_sp800_108,
    parse_response,
)


class TestNtpClientHeader:
    def test_length(self):
        assert len(_NTP_CLIENT_HEADER) == _NTP_HEADER_LEN

    def test_byte0_li_vn_mode(self):
        byte0 = _NTP_CLIENT_HEADER[0]
        li = (byte0 >> 6) & 0x3
        vn = (byte0 >> 3) & 0x7
        mode = byte0 & 0x7
        assert li == 0
        assert vn == 4
        assert mode == 3

    def test_stratum(self):
        assert _NTP_CLIENT_HEADER[1] == 2

    def test_poll(self):
        assert _NTP_CLIENT_HEADER[2] == 10

    def test_rest_is_zeros(self):
        assert all(b == 0 for b in _NTP_CLIENT_HEADER[3:])


# ---------------------------------------------------------------------------
# 68-byte Authenticator request
# ---------------------------------------------------------------------------


class TestBuildRequest:
    def test_total_length(self):
        assert len(build_request(1000)) == _AUTH_LEN

    def test_ntp_header_prefix(self):
        assert build_request(1000)[:_NTP_HEADER_LEN] == _NTP_CLIENT_HEADER

    def test_rid_current(self):
        key_id = struct.unpack("<I", build_request(1000)[48:52])[0]
        assert key_id == 1000

    def test_rid_old(self):
        key_id = struct.unpack("<I", build_request(1000, old_pwd=True)[48:52])[0]
        assert key_id == 1000 ^ _KEY_SELECTOR_OLD
        assert key_id & (1 << 31) != 0

    def test_checksum_zeros(self):
        assert build_request(500)[52:68] == b"\x00" * 16

    def test_different_rids(self):
        p1 = build_request(500)
        p2 = build_request(501)
        assert p1[:48] == p2[:48]
        assert p1[48:52] != p2[48:52]

    def test_rid_zero(self):
        assert struct.unpack("<I", build_request(0)[48:52])[0] == 0

    def test_max_rid(self):
        max_rid = (1 << 31) - 1
        assert struct.unpack("<I", build_request(max_rid)[48:52])[0] == max_rid


# ---------------------------------------------------------------------------
# 120-byte ExtendedAuthenticator request
# ---------------------------------------------------------------------------


class TestBuildExtendedRequest:
    def test_total_length(self):
        assert len(build_extended_request(1000)) == _EXT_AUTH_LEN

    def test_ntp_header_prefix(self):
        assert build_extended_request(1000)[:_NTP_HEADER_LEN] == _NTP_CLIENT_HEADER

    def test_key_id_is_full_rid(self):
        pkt = build_extended_request(1103)
        key_id = struct.unpack("<I", pkt[48:52])[0]
        assert key_id == 1103

    def test_reserved_zero(self):
        assert build_extended_request(1000)[52] == 0x00

    def test_flags_current(self):
        # Bit 0 must always be set - DC requires it as a gate.
        assert build_extended_request(1000, old_pwd=False)[53] == 0x01

    def test_flags_old(self):
        # Same value - no distinction possible at protocol level.
        assert build_extended_request(1000, old_pwd=True)[53] == 0x01

    def test_client_hints_ntlm(self):
        assert build_extended_request(1000)[54] == 0x01

    def test_sig_hash_id_zero(self):
        assert build_extended_request(1000)[55] == 0x00

    def test_checksum_64_zeros(self):
        assert build_extended_request(1000)[56:120] == b"\x00" * 64

    def test_old_pwd_does_not_use_bit31(self):
        """ExtendedAuth uses Flags byte, not bit 31 in Key ID."""
        pkt = build_extended_request(1000, old_pwd=True)
        key_id = struct.unpack("<I", pkt[48:52])[0]
        assert key_id == 1000  # no bit 31


# ---------------------------------------------------------------------------
# Response parsing: 68-byte
# ---------------------------------------------------------------------------


class TestParseAuthResponse:
    def _build(self, rid, md5_hash, salt, old_pwd=False):
        key_selector = _KEY_SELECTOR_OLD if old_pwd else 0
        return salt + struct.pack("<I", rid ^ key_selector) + md5_hash

    def test_valid_68(self):
        resp = parse_response(self._build(1000, b"\xaa" * 16, b"\xbb" * 48))
        assert resp is not None
        assert resp.rid == 1000
        assert resp.md5_hash == b"\xaa" * 16
        assert resp.salt == b"\xbb" * 48
        assert not resp.is_extended
        assert resp.is_md5
        assert not resp.is_sha512

    def test_old_pwd(self):
        resp = parse_response(self._build(1000, b"\xcc" * 16, b"\xdd" * 48, old_pwd=True), old_pwd=True)
        assert resp is not None
        assert resp.rid == 1000

    def test_wrong_length(self):
        assert parse_response(b"\x00" * 67) is None
        assert parse_response(b"\x00" * 69) is None
        assert parse_response(b"") is None

    def test_roundtrip(self):
        pkt = build_request(999)
        reply = b"\xaa" * 48 + pkt[48:52] + b"\xbb" * 16
        resp = parse_response(reply)
        assert resp is not None
        assert resp.rid == 999


# ---------------------------------------------------------------------------
# Response parsing: 120-byte
# ---------------------------------------------------------------------------


class TestParseExtendedResponse:
    def _build(self, rid, checksum_64, salt, sig_hash_id=0x00):
        header = struct.pack("<I B B B B", rid, 0x01, 0x00, 0x00, sig_hash_id)
        return salt + header + checksum_64

    def test_valid_120_always_sha512(self):
        """120-byte responses are always SHA512 regardless of SigHashID."""
        resp = parse_response(self._build(1110, b"\xaa" * 64, b"\xbb" * 48, sig_hash_id=0x00))
        assert resp is not None
        assert resp.rid == 1110
        assert resp.is_extended
        assert resp.sig_hash_id == 0x00
        assert resp.is_sha512  # always SHA512 for extended
        assert not resp.is_md5
        assert resp.checksum == b"\xaa" * 64

    def test_valid_120_sha512_explicit(self):
        resp = parse_response(self._build(1110, b"\xcc" * 64, b"\xdd" * 48, sig_hash_id=0x01))
        assert resp is not None
        assert resp.is_sha512
        assert not resp.is_md5
        assert resp.checksum == b"\xcc" * 64

    def test_sha512_md5_hash_raises(self):
        import pytest

        resp = parse_response(self._build(1110, b"\xee" * 64, b"\xff" * 48, sig_hash_id=0x01))
        with pytest.raises(ValueError, match="HMAC-SHA512"):
            _ = resp.md5_hash

    def test_120_wrong_length_rejected(self):
        assert parse_response(b"\x00" * 119) is None
        assert parse_response(b"\x00" * 121) is None


# ---------------------------------------------------------------------------
# KDF + HMAC-SHA512 crypto
# ---------------------------------------------------------------------------


class TestKdfSp800108:
    def test_output_length_64(self):
        key = kdf_sp800_108(b"\x00" * 16, b"test", b"\x00" * 4, 64)
        assert len(key) == 64

    def test_output_length_32(self):
        key = kdf_sp800_108(b"\x00" * 16, b"test", b"\x00" * 4, 32)
        assert len(key) == 32

    def test_deterministic(self):
        k1 = kdf_sp800_108(b"\xaa" * 16, b"sntp-ms", struct.pack("<I", 1103), 64)
        k2 = kdf_sp800_108(b"\xaa" * 16, b"sntp-ms", struct.pack("<I", 1103), 64)
        assert k1 == k2

    def test_different_keys(self):
        k1 = kdf_sp800_108(b"\xaa" * 16, b"sntp-ms", struct.pack("<I", 1000), 64)
        k2 = kdf_sp800_108(b"\xbb" * 16, b"sntp-ms", struct.pack("<I", 1000), 64)
        assert k1 != k2

    def test_different_contexts(self):
        k1 = kdf_sp800_108(b"\xaa" * 16, b"sntp-ms", struct.pack("<I", 1000), 64)
        k2 = kdf_sp800_108(b"\xaa" * 16, b"sntp-ms", struct.pack("<I", 1001), 64)
        assert k1 != k2


class TestComputeExtendedChecksum:
    def test_output_64_bytes(self):
        result = compute_extended_checksum(b"\xaa" * 16, 1103, b"\xbb" * 48)
        assert len(result) == 64

    def test_deterministic(self):
        r1 = compute_extended_checksum(b"\xcc" * 16, 1000, b"\xdd" * 48)
        r2 = compute_extended_checksum(b"\xcc" * 16, 1000, b"\xdd" * 48)
        assert r1 == r2

    def test_different_nt_hashes(self):
        r1 = compute_extended_checksum(b"\x11" * 16, 1000, b"\x33" * 48)
        r2 = compute_extended_checksum(b"\x22" * 16, 1000, b"\x33" * 48)
        assert r1 != r2

    def test_different_salts(self):
        r1 = compute_extended_checksum(b"\x11" * 16, 1000, b"\x33" * 48)
        r2 = compute_extended_checksum(b"\x11" * 16, 1000, b"\x44" * 48)
        assert r1 != r2

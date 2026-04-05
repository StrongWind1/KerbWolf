"""Tests for NTLM hash extraction from pcap packets."""

import struct

from kerbwolf.core.capture import AttackType, CapturedHash
from kerbwolf.core.ntlmssp import (
    NtlmSessions,
    _classify_ntlm_hash,
    _extract_http_ntlm_tokens,
    _extract_imap_ntlm_tokens,
    _extract_ldap_ntlm_token,
    _extract_pop3_ntlm_tokens,
    _extract_smb_security_blob,
    _extract_smtp_ntlm_tokens,
    _extract_telnet_ntlm_tokens,
    _handle_type2,
    _handle_type3,
    _strip_ip_transport_full,
    _unwrap_spnego,
    try_extract_ntlm,
)
from kerbwolf.models import HashcatMode, RoastResult

# ---------------------------------------------------------------------------
# Helper: build a minimal NTLMSSP Type 2 (CHALLENGE) token
# ---------------------------------------------------------------------------


def _build_ntlmssp_type2(challenge: bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88") -> bytes:
    """Build a minimal NTLMSSP Type 2 (CHALLENGE_MESSAGE).

    Layout per [MS-NLMP] 2.2.1.2:
        0-7:   'NTLMSSP\\x00'
        8-11:  MessageType = 0x00000002
        12-19: TargetNameFields (Len=0, MaxLen=0, Offset=56)
        20-23: NegotiateFlags
        24-31: ServerChallenge (8 bytes)
        32-39: Reserved (8 zero bytes)
        40-47: TargetInfoFields (Len=0, MaxLen=0, Offset=56)
    """
    sig = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", 2)
    # TargetName: Len=0, MaxLen=0, Offset=56
    target_name = struct.pack("<HHI", 0, 0, 56)
    flags = struct.pack("<I", 0x00028233)  # Typical negotiate flags
    reserved = b"\x00" * 8
    # TargetInfo: Len=0, MaxLen=0, Offset=56
    target_info = struct.pack("<HHI", 0, 0, 56)
    return sig + msg_type + target_name + flags + challenge + reserved + target_info


def _build_ntlmssp_type3(
    user: str = "admin",
    domain: str = "CORP",
    nt_response: bytes = b"\xaa" * 48,
    lm_response: bytes = b"\xbb" * 24,
) -> bytes:
    """Build a minimal NTLMSSP Type 3 (AUTHENTICATE_MESSAGE).

    Simplified layout with Unicode strings.
    """
    sig = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", 3)

    user_bytes = user.encode("utf-16-le")
    domain_bytes = domain.encode("utf-16-le")

    # Fixed header is 88 bytes, payload starts at offset 88.
    payload_offset = 88

    # LM Response
    lm_off = payload_offset
    lm_fields = struct.pack("<HHI", len(lm_response), len(lm_response), lm_off)

    # NT Response
    nt_off = lm_off + len(lm_response)
    nt_fields = struct.pack("<HHI", len(nt_response), len(nt_response), nt_off)

    # Domain
    domain_off = nt_off + len(nt_response)
    domain_fields = struct.pack("<HHI", len(domain_bytes), len(domain_bytes), domain_off)

    # User
    user_off = domain_off + len(domain_bytes)
    user_fields = struct.pack("<HHI", len(user_bytes), len(user_bytes), user_off)

    ws_off = user_off + len(user_bytes)
    ws_fields = struct.pack("<HHI", 0, 0, ws_off)  # Workstation
    sess_fields = struct.pack("<HHI", 0, 0, ws_off)  # EncryptedRandomSession
    flags = struct.pack("<I", 0x00000001)  # NTLMSSP_NEGOTIATE_UNICODE

    header = sig + msg_type + lm_fields + nt_fields + domain_fields + user_fields + ws_fields + sess_fields + flags
    # Pad header to 88 bytes if needed.
    header = header.ljust(payload_offset, b"\x00")

    payload = lm_response + nt_response + domain_bytes + user_bytes
    return header + payload


def _build_ipv4_tcp(src_ip_str: str, src_port: int, dst_ip_str: str, dst_port: int, payload: bytes) -> bytes:
    """Build IPv4 + TCP data (no link layer - already stripped)."""
    src_ip = bytes(int(x) for x in src_ip_str.split("."))
    dst_ip = bytes(int(x) for x in dst_ip_str.split("."))
    tcp_header = struct.pack("!HH", src_port, dst_port) + b"\x00" * 8
    tcp_header += bytes([0x50, 0x00]) + b"\x00" * 6
    tcp_data = tcp_header + payload
    ip_header = bytes([0x45, 0x00]) + struct.pack("!H", 20 + len(tcp_data))
    ip_header += b"\x00" * 5 + bytes([6])
    ip_header += b"\x00" * 2 + src_ip + dst_ip
    return ip_header + tcp_data


# ---------------------------------------------------------------------------
# _classify_ntlm_hash
# ---------------------------------------------------------------------------


class TestClassifyNtlmHash:
    def test_ntlmv2(self):
        """NT response > 24 bytes -> NTLMv2."""
        challenge = b"\x11" * 8
        nt_resp = b"\xaa" * 48  # 16 NTProofStr + 32 blob
        lm_resp = b"\x00" * 24
        results = _classify_ntlm_hash("user", "DOMAIN", challenge, nt_resp, lm_resp)
        assert len(results) >= 1
        assert results[0].attack == AttackType.NTLMV2
        assert results[0].username == "user"
        assert results[0].realm == "DOMAIN"
        assert results[0].challenge_hex == challenge.hex()
        assert len(results[0].cipher_hex) == 32  # NTProofStr = 16 bytes = 32 hex

    def test_ntlmv2_with_lmv2_companion(self):
        """NTLMv2 with non-zero 24-byte LM response -> LMv2 companion."""
        challenge = b"\x22" * 8
        nt_resp = b"\xcc" * 48
        lm_resp = b"\xdd" * 24  # Non-zero, so LMv2 companion
        results = _classify_ntlm_hash("user", "DOMAIN", challenge, nt_resp, lm_resp)
        assert len(results) == 2
        assert results[0].attack == AttackType.NTLMV2
        assert results[1].attack == AttackType.NTLMV2

    def test_ntlmv2_no_lmv2_when_zeros(self):
        """NTLMv2 with all-zero LM response -> no LMv2 companion."""
        nt_resp = b"\xcc" * 48
        lm_resp = b"\x00" * 24
        results = _classify_ntlm_hash("user", "D", b"\x11" * 8, nt_resp, lm_resp)
        assert len(results) == 1

    def test_ntlmv1(self):
        """NT response == 24 bytes, non-ESS LM -> NTLMv1."""
        challenge = b"\x33" * 8
        nt_resp = b"\xee" * 24
        lm_resp = b"\xff" * 24
        results = _classify_ntlm_hash("user", "DOMAIN", challenge, nt_resp, lm_resp)
        assert len(results) == 1
        assert results[0].attack == AttackType.NTLMV1
        assert results[0].lm_hex == lm_resp.hex()

    def test_ntlmv1_ess(self):
        """NT response == 24 bytes, LM = ClientChallenge(8) + zeros(16) -> ESS."""
        challenge = b"\x44" * 8
        nt_resp = b"\xee" * 24
        client_challenge = b"\xab" * 8
        lm_resp = client_challenge + b"\x00" * 16
        results = _classify_ntlm_hash("user", "D", challenge, nt_resp, lm_resp)
        assert len(results) == 1
        assert results[0].attack == AttackType.NTLMV1
        # ESS LM format: client_challenge hex + zeros hex
        assert results[0].lm_hex == client_challenge.hex() + ("00" * 16)

    def test_ntlmv1_lm_duplicate_skipped(self):
        """NTLMv1 with LM == NT response -> LM field is empty."""
        nt_resp = b"\xee" * 24
        results = _classify_ntlm_hash("user", "D", b"\x55" * 8, nt_resp, nt_resp)
        assert len(results) == 1
        assert results[0].lm_hex == ""

    def test_empty_nt_response(self):
        """Empty NT response -> no hash."""
        assert _classify_ntlm_hash("user", "D", b"\x66" * 8, b"", b"") == []

    def test_anonymous_skipped(self):
        """No user and no responses -> anonymous, skipped."""
        assert _classify_ntlm_hash("", "D", b"\x77" * 8, b"", b"") == []


# ---------------------------------------------------------------------------
# SPNEGO unwrapping
# ---------------------------------------------------------------------------


class TestUnwrapSpnego:
    def test_bare_ntlmssp(self):
        """Bare NTLMSSP token passes through."""
        token = b"NTLMSSP\x00\x01" + b"\x00" * 20
        assert _unwrap_spnego(token) == token

    def test_empty(self):
        assert _unwrap_spnego(b"") is None

    def test_garbage(self):
        assert _unwrap_spnego(b"\xff\xfe\xfd") is None


# ---------------------------------------------------------------------------
# Type 2 / Type 3 handling
# ---------------------------------------------------------------------------


class TestHandleType2:
    def test_stores_challenge(self):
        sessions: NtlmSessions = {}
        token = _build_ntlmssp_type2(b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22")
        conn_key = ("10.0.0.1", 445, "10.0.0.2", 50000)
        _handle_type2(token, conn_key, sessions)
        assert conn_key in sessions
        assert sessions[conn_key] == b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22"

    def test_invalid_token_no_crash(self):
        sessions: NtlmSessions = {}
        _handle_type2(b"\x00" * 10, ("a", 1, "b", 2), sessions)
        assert len(sessions) == 0


class TestHandleType3:
    def test_extracts_hash_with_matching_challenge(self):
        sessions: NtlmSessions = {}
        challenge = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        conn_key = ("10.0.0.1", 445, "10.0.0.2", 50000)
        sessions[conn_key] = challenge

        nt_resp = b"\xaa" * 48  # NTLMv2 (>24 bytes)
        token = _build_ntlmssp_type3(nt_response=nt_resp, lm_response=b"\x00" * 24)
        results = _handle_type3(token, conn_key, sessions)
        assert len(results) >= 1
        assert results[0].attack == AttackType.NTLMV2

    def test_no_challenge_returns_empty(self):
        sessions: NtlmSessions = {}
        token = _build_ntlmssp_type3()
        results = _handle_type3(token, ("a", 1, "b", 2), sessions)
        assert results == []


# ---------------------------------------------------------------------------
# SMB security blob extraction
# ---------------------------------------------------------------------------


class TestExtractSmbSecurityBlob:
    def test_smb2_session_setup_request(self):
        """SMB2 SESSION_SETUP request with embedded NTLMSSP."""
        # Build minimal SMB2 header (64 bytes) + SESSION_SETUP request.
        ntlmssp_token = b"NTLMSSP\x00\x01" + b"\x00" * 20

        smb2_header = b"\xfeSMB"  # Signature
        smb2_header += struct.pack("<H", 64)  # StructureSize
        smb2_header += b"\x00" * 2  # CreditCharge
        smb2_header += b"\x00" * 4  # Status
        smb2_header += struct.pack("<H", 1)  # Command = SESSION_SETUP
        smb2_header += b"\x00" * (64 - len(smb2_header))  # Pad to 64

        # SESSION_SETUP request: StructureSize=25
        cmd = struct.pack("<H", 25)  # StructureSize
        cmd += b"\x00" * 10  # Flags, SecurityMode, Capabilities, Channel
        # SecurityBufferOffset = 64 + 24 = 88 from SMB2 header start
        cmd += struct.pack("<H", 64 + 24)  # SecurityBufferOffset
        cmd += struct.pack("<H", len(ntlmssp_token))  # SecurityBufferLength
        cmd += b"\x00" * 8  # PreviousSessionId
        cmd += ntlmssp_token

        packet = smb2_header + cmd
        blob = _extract_smb_security_blob(packet)
        assert blob is not None
        assert blob[:8] == b"NTLMSSP\x00"

    def test_non_session_setup_returns_none(self):
        """SMB2 packet with non-SESSION_SETUP command returns None."""
        smb2_header = b"\xfeSMB"
        smb2_header += struct.pack("<H", 64)
        smb2_header += b"\x00" * 2
        smb2_header += b"\x00" * 4
        smb2_header += struct.pack("<H", 5)  # Command = TREE_CONNECT (not SESSION_SETUP)
        smb2_header += b"\x00" * (64 - len(smb2_header))
        smb2_header += b"\x00" * 20  # Some payload

        assert _extract_smb_security_blob(smb2_header) is None

    def test_netbios_header_stripped(self):
        """NetBIOS 4-byte session header is stripped before SMB parsing."""
        ntlmssp_token = b"NTLMSSP\x00\x01" + b"\x00" * 20
        smb2_header = b"\xfeSMB"
        smb2_header += struct.pack("<H", 64)
        smb2_header += b"\x00" * 2 + b"\x00" * 4
        smb2_header += struct.pack("<H", 1)  # SESSION_SETUP
        smb2_header += b"\x00" * (64 - len(smb2_header))

        cmd = struct.pack("<H", 25) + b"\x00" * 10
        cmd += struct.pack("<H", 64 + 24) + struct.pack("<H", len(ntlmssp_token))
        cmd += b"\x00" * 8 + ntlmssp_token

        smb_data = smb2_header + cmd
        # Prepend NetBIOS header.
        nb_len = len(smb_data)
        nb_header = b"\x00" + struct.pack("!I", nb_len)[1:]  # 3-byte length
        packet = nb_header + smb_data

        blob = _extract_smb_security_blob(packet)
        assert blob is not None

    def test_garbage_returns_none(self):
        assert _extract_smb_security_blob(b"\xff\xfe\xfd") is None
        assert _extract_smb_security_blob(b"") is None


# ---------------------------------------------------------------------------
# HTTP NTLM extraction
# ---------------------------------------------------------------------------


class TestExtractHttpNtlm:
    def test_authorization_header(self):
        """Extract NTLMSSP from HTTP Authorization header."""
        import base64

        token = b"NTLMSSP\x00\x03" + b"\x00" * 20
        b64 = base64.b64encode(token).decode()
        payload = f"POST /resource HTTP/1.1\r\nAuthorization: NTLM {b64}\r\n\r\n".encode()
        tokens = _extract_http_ntlm_tokens(payload)
        assert len(tokens) == 1
        assert tokens[0][:8] == b"NTLMSSP\x00"

    def test_www_authenticate_header(self):
        """Extract NTLMSSP from HTTP WWW-Authenticate header."""
        import base64

        token = b"NTLMSSP\x00\x02" + b"\x00" * 40
        b64 = base64.b64encode(token).decode()
        payload = f"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n".encode()
        tokens = _extract_http_ntlm_tokens(payload)
        assert len(tokens) == 1

    def test_no_ntlm_header(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert _extract_http_ntlm_tokens(payload) == []


# ---------------------------------------------------------------------------
# LDAP NTLM extraction
# ---------------------------------------------------------------------------


class TestExtractLdapNtlm:
    def test_bare_ntlmssp_in_payload(self):
        """Find NTLMSSP signature embedded in LDAP payload."""
        prefix = b"\x30\x84\x00\x00\x00\x50"  # Fake LDAP envelope
        token = b"NTLMSSP\x00\x03" + b"\x00" * 20
        payload = prefix + token
        result = _extract_ldap_ntlm_token(payload)
        assert result is not None
        assert result[:8] == b"NTLMSSP\x00"

    def test_no_ntlmssp(self):
        assert _extract_ldap_ntlm_token(b"\x30\x00\x00\x00") is None


# ---------------------------------------------------------------------------
# IP transport parsing with addresses
# ---------------------------------------------------------------------------


class TestStripIpTransportFull:
    def test_ipv4_tcp(self):
        """IPv4 + TCP packet with addresses extracted."""
        # IPv4 header: version=4, IHL=5, proto=TCP(6)
        src_ip = b"\x0a\x00\x00\x01"  # 10.0.0.1
        dst_ip = b"\x0a\x00\x00\x02"  # 10.0.0.2
        ip_header = bytes([0x45, 0x00]) + struct.pack("!H", 40)  # Total len
        ip_header += b"\x00" * 5 + bytes([6])  # proto=TCP
        ip_header += b"\x00" * 2 + src_ip + dst_ip

        # TCP header: src=50000, dst=445, data_offset=5 (20 bytes)
        tcp_header = struct.pack("!HH", 50000, 445) + b"\x00" * 8
        tcp_header += bytes([0x50, 0x00]) + b"\x00" * 6  # data_offset = 5*4=20

        payload = b"test data"
        result = _strip_ip_transport_full(ip_header + tcp_header + payload)
        assert result is not None
        data, src, src_port, dst, dst_port, proto = result
        assert src == "10.0.0.1"
        assert dst == "10.0.0.2"
        assert src_port == 50000
        assert dst_port == 445
        assert proto == 6
        assert data == payload

    def test_non_tcp_returns_none(self):
        """UDP packet returns None (NTLM is TCP only)."""
        ip_header = bytes([0x45, 0x00]) + struct.pack("!H", 28)
        ip_header += b"\x00" * 5 + bytes([17])  # proto=UDP
        ip_header += b"\x00" * 2 + b"\x0a" * 4 + b"\x0a" * 4
        udp = struct.pack("!HH", 123, 123) + b"\x00" * 4
        assert _strip_ip_transport_full(ip_header + udp) is None

    def test_short_data_returns_none(self):
        assert _strip_ip_transport_full(b"\x45\x00") is None


# ---------------------------------------------------------------------------
# Full pipeline: try_extract_ntlm with synthetic IP data
# ---------------------------------------------------------------------------


class TestTryExtractNtlm:
    def _build_smb2_session_setup(self, ntlmssp_token):
        """Wrap an NTLMSSP token in a minimal SMB2 SESSION_SETUP packet."""
        smb2_hdr = b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 2 + b"\x00" * 4
        smb2_hdr += struct.pack("<H", 1)  # SESSION_SETUP
        smb2_hdr += b"\x00" * (64 - len(smb2_hdr))

        cmd = struct.pack("<H", 25) + b"\x00" * 10
        cmd += struct.pack("<H", 64 + 24) + struct.pack("<H", len(ntlmssp_token))
        cmd += b"\x00" * 8 + ntlmssp_token
        return smb2_hdr + cmd

    def test_type2_then_type3_produces_hash(self):
        """Full pipeline: Type 2 on port 445 followed by Type 3 produces hash."""
        sessions: NtlmSessions = {}
        challenge = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22"

        # Server -> Client: Type 2 (CHALLENGE)
        type2 = _build_ntlmssp_type2(challenge)
        smb2_type2 = self._build_smb2_session_setup(type2)
        ip_type2 = _build_ipv4_tcp("10.0.0.1", 445, "10.0.0.2", 50000, smb2_type2)
        result2 = try_extract_ntlm(ip_type2, sessions)
        assert result2 == []  # Type 2 stores challenge, no output
        assert len(sessions) == 1

        # Client -> Server: Type 3 (AUTHENTICATE) with NTLMv2 response
        nt_resp = b"\xcc" * 48  # >24 bytes = NTLMv2
        type3 = _build_ntlmssp_type3(user="admin", domain="CORP", nt_response=nt_resp, lm_response=b"\x00" * 24)
        smb2_type3 = self._build_smb2_session_setup(type3)
        ip_type3 = _build_ipv4_tcp("10.0.0.2", 50000, "10.0.0.1", 445, smb2_type3)
        result3 = try_extract_ntlm(ip_type3, sessions)
        assert len(result3) >= 1
        assert result3[0].attack == AttackType.NTLMV2
        assert result3[0].username == "admin"
        assert result3[0].challenge_hex == challenge.hex()

    def test_type3_without_type2_returns_empty(self):
        """Type 3 without a prior Type 2 returns empty (no challenge)."""
        sessions: NtlmSessions = {}
        type3 = _build_ntlmssp_type3()
        smb2 = self._build_smb2_session_setup(type3)
        ip_data = _build_ipv4_tcp("10.0.0.2", 50000, "10.0.0.1", 445, smb2)
        assert try_extract_ntlm(ip_data, sessions) == []

    def test_non_smb_port_skipped(self):
        """TCP on a non-NTLM port is ignored."""
        sessions: NtlmSessions = {}
        type2 = _build_ntlmssp_type2()
        smb2 = self._build_smb2_session_setup(type2)
        ip_data = _build_ipv4_tcp("10.0.0.1", 9999, "10.0.0.2", 9999, smb2)
        assert try_extract_ntlm(ip_data, sessions) == []

    def test_garbage_no_crash(self):
        """Garbage data doesn't crash."""
        sessions: NtlmSessions = {}
        ip_data = _build_ipv4_tcp("10.0.0.1", 445, "10.0.0.2", 50000, b"\xff" * 100)
        assert try_extract_ntlm(ip_data, sessions) == []

    def test_http_port_80(self):
        """NTLM over HTTP port 80 - Type 2 and Type 3."""
        import base64

        sessions: NtlmSessions = {}
        challenge = b"\x11" * 8

        # Server -> Client: HTTP 401 with Type 2
        type2 = _build_ntlmssp_type2(challenge)
        b64_type2 = base64.b64encode(type2).decode()
        http_resp = f"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {b64_type2}\r\n\r\n".encode()
        ip_type2 = _build_ipv4_tcp("10.0.0.1", 80, "10.0.0.2", 50000, http_resp)
        try_extract_ntlm(ip_type2, sessions)
        assert len(sessions) == 1

        # Client -> Server: POST with Type 3
        nt_resp = b"\xcc" * 48  # NTLMv2
        type3 = _build_ntlmssp_type3(user="webuser", domain="CORP", nt_response=nt_resp, lm_response=b"\x00" * 24)
        b64_type3 = base64.b64encode(type3).decode()
        http_req = f"POST /resource HTTP/1.1\r\nAuthorization: NTLM {b64_type3}\r\n\r\n".encode()
        ip_type3 = _build_ipv4_tcp("10.0.0.2", 50000, "10.0.0.1", 80, http_req)
        results = try_extract_ntlm(ip_type3, sessions)
        assert len(results) >= 1
        assert results[0].username == "webuser"


# ---------------------------------------------------------------------------
# _captured_to_result for NTLM types
# ---------------------------------------------------------------------------


class TestCapturedToResultNtlm:
    def test_ntlmv2_result(self):
        from kerbwolf.attacks.extract import _captured_to_result
        from kerbwolf.models import HashFormat

        h = CapturedHash(
            attack=AttackType.NTLMV2,
            username="admin",
            realm="CORP",
            spn="",
            etype=0,
            cipher_hex="aa" * 16,
            challenge_hex="bb" * 8,
            ntlm_blob_hex="cc" * 32,
        )
        result = _captured_to_result(h, HashFormat.HASHCAT)
        assert isinstance(result, RoastResult)
        assert result.hashcat_mode == HashcatMode.NTLMV2
        assert "admin" in result.hash_string
        assert "CORP" in result.hash_string
        assert "::" in result.hash_string

    def test_ntlmv1_result(self):
        from kerbwolf.attacks.extract import _captured_to_result
        from kerbwolf.models import HashFormat

        h = CapturedHash(
            attack=AttackType.NTLMV1,
            username="user",
            realm="DOMAIN",
            spn="",
            etype=0,
            cipher_hex="dd" * 24,
            challenge_hex="ee" * 8,
            lm_hex="ff" * 24,
        )
        result = _captured_to_result(h, HashFormat.HASHCAT)
        assert result.hashcat_mode == HashcatMode.NTLMV1
        assert "user::DOMAIN:" in result.hash_string


# ---------------------------------------------------------------------------
# CLI summary counter
# ---------------------------------------------------------------------------


class TestCliNtlmSummary:
    def test_ntlm_summary(self, capsys):
        from kerbwolf.cli.extract import _output_results
        from kerbwolf.log import Logger

        results = [
            RoastResult(username="u", realm="D", spn="", etype=0, hash_string="admin::CORP:aabb:ccdd:eeff", hashcat_mode=5600),
            RoastResult(username="u", realm="D", spn="", etype=0, hash_string="user::DOMAIN:1122:3344:5566", hashcat_mode=5500),
        ]
        _output_results(results, None, Logger())
        err = capsys.readouterr().err
        assert "NTLMv2" in err
        assert "NTLMv1" in err


# ---------------------------------------------------------------------------
# MS-NTHT: HTTP NTLM (all 4 header types)
# ---------------------------------------------------------------------------


class TestHttpNtlmHeaders:
    """Test all HTTP headers per [MS-NTHT]."""

    def _make_token(self, msg_type: int = 3) -> bytes:
        return b"NTLMSSP\x00" + bytes([msg_type]) + b"\x00" * 20

    def test_authorization(self):
        import base64

        b64 = base64.b64encode(self._make_token(3)).decode()
        payload = f"POST / HTTP/1.1\r\nAuthorization: NTLM {b64}\r\n\r\n".encode()
        tokens = _extract_http_ntlm_tokens(payload)
        assert len(tokens) == 1
        assert tokens[0][8] == 3

    def test_www_authenticate(self):
        import base64

        b64 = base64.b64encode(self._make_token(2)).decode()
        payload = f"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n".encode()
        tokens = _extract_http_ntlm_tokens(payload)
        assert len(tokens) == 1
        assert tokens[0][8] == 2

    def test_proxy_authorization(self):
        import base64

        b64 = base64.b64encode(self._make_token(3)).decode()
        payload = f"CONNECT host:443 HTTP/1.1\r\nProxy-Authorization: NTLM {b64}\r\n\r\n".encode()
        tokens = _extract_http_ntlm_tokens(payload)
        assert len(tokens) == 1

    def test_proxy_authenticate(self):
        import base64

        b64 = base64.b64encode(self._make_token(2)).decode()
        payload = f"HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: NTLM {b64}\r\n\r\n".encode()
        tokens = _extract_http_ntlm_tokens(payload)
        assert len(tokens) == 1

    def test_case_insensitive(self):
        import base64

        b64 = base64.b64encode(self._make_token(3)).decode()
        payload = f"POST / HTTP/1.1\r\nAUTHORIZATION: ntlm {b64}\r\n\r\n".encode()
        tokens = _extract_http_ntlm_tokens(payload)
        assert len(tokens) == 1

    def test_no_ntlm_header(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert _extract_http_ntlm_tokens(payload) == []

    def test_basic_auth_not_matched(self):
        payload = b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
        assert _extract_http_ntlm_tokens(payload) == []

    def test_invalid_base64_skipped(self):
        payload = b"POST / HTTP/1.1\r\nAuthorization: NTLM !!!invalid!!!\r\n\r\n"
        assert _extract_http_ntlm_tokens(payload) == []

    def test_http_full_pipeline(self):
        """Full pipeline: HTTP Type 2 + Type 3 on port 80."""
        import base64

        sessions: NtlmSessions = {}
        challenge = b"\xaa" * 8

        type2 = _build_ntlmssp_type2(challenge)
        b64_2 = base64.b64encode(type2).decode()
        resp = f"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {b64_2}\r\n\r\n".encode()
        ip_2 = _build_ipv4_tcp("10.0.0.1", 80, "10.0.0.2", 50000, resp)
        try_extract_ntlm(ip_2, sessions)
        assert len(sessions) == 1

        type3 = _build_ntlmssp_type3(user="httpuser", domain="CORP", nt_response=b"\xdd" * 48)
        b64_3 = base64.b64encode(type3).decode()
        req = f"POST / HTTP/1.1\r\nAuthorization: NTLM {b64_3}\r\n\r\n".encode()
        ip_3 = _build_ipv4_tcp("10.0.0.2", 50000, "10.0.0.1", 80, req)
        results = try_extract_ntlm(ip_3, sessions)
        assert len(results) >= 1
        assert results[0].username == "httpuser"


# ---------------------------------------------------------------------------
# MS-SMTPNTLM: SMTP NTLM (ports 25/587)
# ---------------------------------------------------------------------------


class TestSmtpNtlmExtraction:
    """Test SMTP NTLM extraction per [MS-SMTPNTLM]."""

    def test_334_challenge(self):
        """Server 334 response with base64 Type 2."""
        import base64

        type2 = _build_ntlmssp_type2()
        b64 = base64.b64encode(type2).decode()
        payload = f"334 {b64}\r\n".encode()
        tokens = _extract_smtp_ntlm_tokens(payload)
        assert len(tokens) == 1
        assert tokens[0][8] == 2

    def test_auth_ntlm_with_inline_type1(self):
        """AUTH NTLM with inline base64 Type 1."""
        import base64

        type1 = b"NTLMSSP\x00\x01" + b"\x00" * 20
        b64 = base64.b64encode(type1).decode()
        payload = f"AUTH NTLM {b64}\r\n".encode()
        tokens = _extract_smtp_ntlm_tokens(payload)
        assert len(tokens) == 1
        assert tokens[0][8] == 1

    def test_bare_base64_type3(self):
        """Bare base64 line containing Type 3."""
        import base64

        type3 = _build_ntlmssp_type3()
        b64 = base64.b64encode(type3).decode()
        payload = f"{b64}\r\n".encode()
        tokens = _extract_smtp_ntlm_tokens(payload)
        assert len(tokens) == 1
        assert tokens[0][8] == 3

    def test_no_ntlm(self):
        payload = b"EHLO example.com\r\n250-smtp.example.com\r\n"
        assert _extract_smtp_ntlm_tokens(payload) == []

    def test_smtp_full_pipeline_port_25(self):
        """Full pipeline: SMTP Type 2 + Type 3 on port 25."""
        import base64

        sessions: NtlmSessions = {}
        challenge = b"\xbb" * 8

        type2 = _build_ntlmssp_type2(challenge)
        b64_2 = base64.b64encode(type2).decode()
        smtp_resp = f"334 {b64_2}\r\n".encode()
        ip_2 = _build_ipv4_tcp("10.0.0.1", 25, "10.0.0.2", 50000, smtp_resp)
        try_extract_ntlm(ip_2, sessions)
        assert len(sessions) == 1

        type3 = _build_ntlmssp_type3(user="mailuser", domain="CORP", nt_response=b"\xee" * 48)
        b64_3 = base64.b64encode(type3).decode()
        smtp_auth = f"{b64_3}\r\n".encode()
        ip_3 = _build_ipv4_tcp("10.0.0.2", 50000, "10.0.0.1", 25, smtp_auth)
        results = try_extract_ntlm(ip_3, sessions)
        assert len(results) >= 1
        assert results[0].username == "mailuser"

    def test_smtp_port_587(self):
        """SMTP submission port 587 is also recognized."""
        import base64

        sessions: NtlmSessions = {}
        type2 = _build_ntlmssp_type2(b"\xcc" * 8)
        smtp_resp = f"334 {base64.b64encode(type2).decode()}\r\n".encode()
        ip_2 = _build_ipv4_tcp("10.0.0.1", 587, "10.0.0.2", 50000, smtp_resp)
        try_extract_ntlm(ip_2, sessions)
        assert len(sessions) == 1


# ---------------------------------------------------------------------------
# MS-POP3: POP3 NTLM (port 110)
# ---------------------------------------------------------------------------


class TestPop3NtlmExtraction:
    """Test POP3 NTLM extraction per [MS-POP3]."""

    def test_challenge_response(self):
        """Server '+ <base64>' challenge."""
        import base64

        type2 = _build_ntlmssp_type2()
        b64 = base64.b64encode(type2).decode()
        payload = f"+ {b64}\r\n".encode()
        tokens = _extract_pop3_ntlm_tokens(payload)
        assert len(tokens) == 1
        assert tokens[0][8] == 2

    def test_bare_base64_type3(self):
        """Client bare base64 Type 3."""
        import base64

        type3 = _build_ntlmssp_type3()
        b64 = base64.b64encode(type3).decode()
        payload = f"{b64}\r\n".encode()
        tokens = _extract_pop3_ntlm_tokens(payload)
        assert len(tokens) == 1

    def test_ok_response_not_matched(self):
        """'+OK' response is not matched as a challenge."""
        payload = b"+OK POP3 server ready\r\n"
        assert _extract_pop3_ntlm_tokens(payload) == []

    def test_pop3_full_pipeline(self):
        """Full pipeline: POP3 Type 2 + Type 3 on port 110."""
        import base64

        sessions: NtlmSessions = {}
        challenge = b"\xdd" * 8

        type2 = _build_ntlmssp_type2(challenge)
        b64_2 = base64.b64encode(type2).decode()
        pop3_resp = f"+ {b64_2}\r\n".encode()
        ip_2 = _build_ipv4_tcp("10.0.0.1", 110, "10.0.0.2", 50000, pop3_resp)
        try_extract_ntlm(ip_2, sessions)
        assert len(sessions) == 1

        type3 = _build_ntlmssp_type3(user="popuser", domain="CORP", nt_response=b"\xff" * 48)
        b64_3 = base64.b64encode(type3).decode()
        pop3_auth = f"{b64_3}\r\n".encode()
        ip_3 = _build_ipv4_tcp("10.0.0.2", 50000, "10.0.0.1", 110, pop3_auth)
        results = try_extract_ntlm(ip_3, sessions)
        assert len(results) >= 1
        assert results[0].username == "popuser"


# ---------------------------------------------------------------------------
# MS-TNAP: Telnet NTLM (port 23)
# ---------------------------------------------------------------------------


class TestTelnetNtlmExtraction:
    """Test Telnet NTLM extraction per [MS-TNAP]."""

    def _build_telnet_ntlm_subneg(self, ntlm_cmd: int, ntlm_data: bytes, *, is_reply: bool = False) -> bytes:
        """Build a Telnet IAC SB AUTH IS/REPLY subnegotiation frame."""
        modifier = 0x00
        is_or_reply = 0x03 if is_reply else 0x00  # IS=0, REPLY=3
        data_size = struct.pack("<I", len(ntlm_data))
        buffer_type = struct.pack("<I", 0x00000002)
        subneg_body = bytes([is_or_reply, 0x0F, modifier, ntlm_cmd]) + data_size + buffer_type + ntlm_data
        return bytes([0xFF, 0xFA, 0x25]) + subneg_body + bytes([0xFF, 0xF0])

    def test_type2_challenge(self):
        """Telnet REPLY with NTLM_CommandCode=0x01 (CHALLENGE)."""
        type2 = _build_ntlmssp_type2()
        frame = self._build_telnet_ntlm_subneg(0x01, type2, is_reply=True)
        tokens = _extract_telnet_ntlm_tokens(frame)
        assert len(tokens) == 1
        assert tokens[0][8] == 2

    def test_type3_authenticate(self):
        """Telnet IS with NTLM_CommandCode=0x02 (AUTHENTICATE)."""
        type3 = _build_ntlmssp_type3()
        frame = self._build_telnet_ntlm_subneg(0x02, type3)
        tokens = _extract_telnet_ntlm_tokens(frame)
        assert len(tokens) == 1
        assert tokens[0][8] == 3

    def test_type1_negotiate(self):
        """Telnet IS with NTLM_CommandCode=0x00 (NEGOTIATE)."""
        type1 = b"NTLMSSP\x00\x01" + b"\x00" * 20
        frame = self._build_telnet_ntlm_subneg(0x00, type1)
        tokens = _extract_telnet_ntlm_tokens(frame)
        assert len(tokens) == 1
        assert tokens[0][8] == 1

    def test_accept_reject_no_data(self):
        """NTLM_CommandCode 0x03 (ACCEPT) and 0x04 (REJECT) have no data."""
        frame = bytes([0xFF, 0xFA, 0x25, 0x03, 0x0F, 0x00, 0x03, 0xFF, 0xF0])
        tokens = _extract_telnet_ntlm_tokens(frame)
        assert tokens == []

    def test_non_ntlm_auth_type(self):
        """Non-NTLM auth type (not 0x0F) is ignored."""
        subneg = bytes([0x00, 0x05, 0x00, 0x00]) + b"\x00" * 12
        frame = bytes([0xFF, 0xFA, 0x25]) + subneg + bytes([0xFF, 0xF0])
        assert _extract_telnet_ntlm_tokens(frame) == []

    def test_empty_payload(self):
        assert _extract_telnet_ntlm_tokens(b"") == []

    def test_garbage(self):
        assert _extract_telnet_ntlm_tokens(b"\x00" * 100) == []

    def test_telnet_full_pipeline(self):
        """Full pipeline: Telnet Type 2 + Type 3 on port 23."""
        sessions: NtlmSessions = {}
        challenge = b"\xee" * 8

        type2 = _build_ntlmssp_type2(challenge)
        frame2 = self._build_telnet_ntlm_subneg(0x01, type2, is_reply=True)
        ip_2 = _build_ipv4_tcp("10.0.0.1", 23, "10.0.0.2", 50000, frame2)
        try_extract_ntlm(ip_2, sessions)
        assert len(sessions) == 1

        type3 = _build_ntlmssp_type3(user="teluser", domain="CORP", nt_response=b"\xab" * 48)
        frame3 = self._build_telnet_ntlm_subneg(0x02, type3)
        ip_3 = _build_ipv4_tcp("10.0.0.2", 50000, "10.0.0.1", 23, frame3)
        results = try_extract_ntlm(ip_3, sessions)
        assert len(results) >= 1
        assert results[0].username == "teluser"


# ---------------------------------------------------------------------------
# WinRM: HTTP NTLM on ports 5985/5986
# ---------------------------------------------------------------------------


class TestWinRmNtlmExtraction:
    """Test WinRM NTLM extraction (HTTP on ports 5985/5986)."""

    def test_winrm_port_5985(self):
        """WinRM HTTP port 5985 recognized for NTLM."""
        import base64

        sessions: NtlmSessions = {}
        challenge = b"\xaa" * 8

        type2 = _build_ntlmssp_type2(challenge)
        b64_2 = base64.b64encode(type2).decode()
        resp = f"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {b64_2}\r\n\r\n".encode()
        ip_2 = _build_ipv4_tcp("10.0.0.1", 5985, "10.0.0.2", 50000, resp)
        try_extract_ntlm(ip_2, sessions)
        assert len(sessions) == 1

        type3 = _build_ntlmssp_type3(user="winrmuser", domain="CORP", nt_response=b"\xbb" * 48)
        b64_3 = base64.b64encode(type3).decode()
        req = f"POST /wsman HTTP/1.1\r\nAuthorization: NTLM {b64_3}\r\n\r\n".encode()
        ip_3 = _build_ipv4_tcp("10.0.0.2", 50000, "10.0.0.1", 5985, req)
        results = try_extract_ntlm(ip_3, sessions)
        assert len(results) >= 1
        assert results[0].username == "winrmuser"

    def test_winrm_port_5986(self):
        """WinRM HTTPS port 5986 recognized (unencrypted pcap only)."""
        import base64

        sessions: NtlmSessions = {}
        type2 = _build_ntlmssp_type2(b"\xcc" * 8)
        b64 = base64.b64encode(type2).decode()
        resp = f"HTTP/1.1 401\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n".encode()
        ip_2 = _build_ipv4_tcp("10.0.0.1", 5986, "10.0.0.2", 50000, resp)
        try_extract_ntlm(ip_2, sessions)
        assert len(sessions) == 1


# ---------------------------------------------------------------------------
# MS-OXIMAP: IMAP NTLM (port 143)
# ---------------------------------------------------------------------------


class TestImapNtlmExtraction:
    """Test IMAP NTLM extraction per [MS-OXIMAP]."""

    def test_challenge_response(self):
        """Server '+ <base64>' challenge."""
        import base64

        type2 = _build_ntlmssp_type2()
        b64 = base64.b64encode(type2).decode()
        payload = f"+ {b64}\r\n".encode()
        tokens = _extract_imap_ntlm_tokens(payload)
        assert len(tokens) == 1
        assert tokens[0][8] == 2

    def test_authenticate_ntlm_inline_type1(self):
        """AUTHENTICATE NTLM with inline base64 Type 1."""
        import base64

        type1 = b"NTLMSSP\x00\x01" + b"\x00" * 20
        b64 = base64.b64encode(type1).decode()
        payload = f"A001 AUTHENTICATE NTLM {b64}\r\n".encode()
        tokens = _extract_imap_ntlm_tokens(payload)
        assert len(tokens) == 1
        assert tokens[0][8] == 1

    def test_bare_base64_type3(self):
        """Client bare base64 Type 3."""
        import base64

        type3 = _build_ntlmssp_type3()
        b64 = base64.b64encode(type3).decode()
        payload = f"{b64}\r\n".encode()
        tokens = _extract_imap_ntlm_tokens(payload)
        assert len(tokens) == 1

    def test_no_ntlm(self):
        payload = b"* OK IMAP4rev1 Service Ready\r\nA001 LOGIN user pass\r\n"
        assert _extract_imap_ntlm_tokens(payload) == []

    def test_imap_full_pipeline(self):
        """Full pipeline: IMAP Type 2 + Type 3 on port 143."""
        import base64

        sessions: NtlmSessions = {}
        challenge = b"\xff" * 8

        type2 = _build_ntlmssp_type2(challenge)
        b64_2 = base64.b64encode(type2).decode()
        imap_resp = f"+ {b64_2}\r\n".encode()
        ip_2 = _build_ipv4_tcp("10.0.0.1", 143, "10.0.0.2", 50000, imap_resp)
        try_extract_ntlm(ip_2, sessions)
        assert len(sessions) == 1

        type3 = _build_ntlmssp_type3(user="imapuser", domain="CORP", nt_response=b"\xab" * 48)
        b64_3 = base64.b64encode(type3).decode()
        imap_auth = f"{b64_3}\r\n".encode()
        ip_3 = _build_ipv4_tcp("10.0.0.2", 50000, "10.0.0.1", 143, imap_auth)
        results = try_extract_ntlm(ip_3, sessions)
        assert len(results) >= 1
        assert results[0].username == "imapuser"

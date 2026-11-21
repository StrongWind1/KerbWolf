# SPDX-License-Identifier: Apache-2.0
"""IPv6 extension header traversal shared by the pcap extractors.

Both the Kerberos/SNTP extractor (``kerbwolf.core.capture``) and the NTLM
extractor (``kerbwolf.core.ntlmssp``) walk the IPv6 extension header chain
to reach the TCP/UDP header.  It lives here so neither has to import the other.
"""

from __future__ import annotations

# IPv6 extension header types that must be skipped to reach TCP/UDP.
# Each has a Next Header field at byte 0 and a Header Extension Length at byte 1.
_IPV6_EXTENSION_HEADERS = frozenset(
    {
        0,  # Hop-by-Hop Options
        43,  # Routing
        44,  # Fragment
        50,  # ESP (Encapsulating Security Payload)
        51,  # AH (Authentication Header)
        60,  # Destination Options
        135,  # Mobility
        139,  # HIP (Host Identity Protocol)
        140,  # Shim6
    }
)

# The Fragment header has no length field: it is always 8 bytes (RFC 8200 section 4.5).
_IPV6_FRAGMENT_HEADER = 44
_IPV6_FRAGMENT_HEADER_LEN = 8


def skip_ipv6_extensions(next_header: int, data: bytes) -> tuple[int, bytes]:
    """Walk IPv6 extension header chain to reach the transport layer.

    Returns ``(proto, transport_data)`` where *proto* is the final Next Header
    value (e.g. TCP=6 or UDP=17) and *transport_data* starts at the transport
    header.  Handles Hop-by-Hop, Routing, Fragment, Destination Options, AH,
    and other standard extension headers per RFC 8200 section 4.
    """
    offset = 0
    proto = next_header
    while proto in _IPV6_EXTENSION_HEADERS and offset < len(data):
        if proto == _IPV6_FRAGMENT_HEADER:
            if offset + _IPV6_FRAGMENT_HEADER_LEN > len(data):
                break
            proto = data[offset]
            offset += _IPV6_FRAGMENT_HEADER_LEN
        else:
            # All other extension headers: Next Header at byte 0,
            # Header Extension Length at byte 1 (in 8-octet units, not counting first 8).
            if offset + 2 > len(data):
                break
            proto = data[offset]
            ext_len = (data[offset + 1] + 1) * 8
            offset += ext_len
    return int(proto), data[offset:]

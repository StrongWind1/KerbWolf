"""DNS resolution helpers for Kerberos domain controllers.

Provides low-level helpers used by ``cli._common.resolve_context()``:

- ``resolve_srv()`` - SRV record lookup (returns hostname)
- ``resolve_host()`` - A/AAAA lookup (returns IP)
- ``is_ip()`` - IPv4/IPv6 detection

Supports both IPv4 and IPv6.
"""

from __future__ import annotations

import logging
import socket

import dns.resolver

_log = logging.getLogger(__name__)


def is_ip(host: str) -> bool:
    """Return ``True`` if *host* looks like an IPv4 or IPv6 address."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
        except OSError:
            continue
        else:
            return True
    return False


def resolve_srv(name: str) -> str | None:
    """Resolve a DNS SRV record and return the target hostname, or ``None``.

    Returns ``None`` if the lookup fails (NXDOMAIN, timeout, etc.).
    """
    _log.debug("SRV lookup: %s", name)
    try:
        answers = dns.resolver.resolve(name, "SRV")
        if answers:
            target = str(answers[0].target).rstrip(".")
            _log.info("SRV: %s → %s", name, target)
            return target
    except Exception:  # noqa: BLE001
        _log.debug("SRV lookup failed for %s", name)
    return None


def resolve_host(hostname: str) -> str | None:
    """Resolve a hostname to an IPv4 or IPv6 address string.

    Prefers IPv4 for compatibility.  Returns ``None`` on failure.
    """
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if results:
            for family, _type, _proto, _canonname, sockaddr in results:
                if family == socket.AF_INET:
                    _log.debug("Resolved %s → %s (IPv4)", hostname, sockaddr[0])
                    return str(sockaddr[0])
            ip = str(results[0][4][0])
            _log.debug("Resolved %s → %s (IPv6)", hostname, ip)
            return ip
    except (socket.gaierror, OSError):
        _log.debug("Failed to resolve %s", hostname)
    return None

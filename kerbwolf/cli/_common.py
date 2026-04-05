"""Shared CLI utilities - argument groups, credential parsing, target collection, output."""

from __future__ import annotations

import argparse  # noqa: TC003
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from kerbwolf import __version__
from kerbwolf.core.ccache import get_ccache_info
from kerbwolf.core.ldap import connect, find_all_users
from kerbwolf.core.resolve import is_ip, resolve_host, resolve_srv
from kerbwolf.models import KerberosContext, KerberosCredential, RoastResult

if TYPE_CHECKING:
    import ldap3

    from kerbwolf.log import Logger

_ETYPE_CHOICES = ["des-cbc-crc", "des-cbc-md5", "rc4", "aes128", "aes256"]


# ---------------------------------------------------------------------------
# Shared argument groups
# ---------------------------------------------------------------------------


def add_connection_args(parser: argparse.ArgumentParser) -> None:
    """Add connection flags.  ``-d`` and ``--dc-ip`` are optional when using ``-k -c``."""
    grp = parser.add_argument_group("connection")
    grp.add_argument("-d", "--domain", help="Domain FQDN (auto-detected from ccache when using -k -c)")
    grp.add_argument("--dc-ip", metavar="IP", help="Domain controller IP or hostname (resolved from domain if omitted)")
    grp.add_argument("--dc-hostname", metavar="HOST", help="DC FQDN for Kerberos SPN (auto-detected if omitted)")
    grp.add_argument("--transport", choices=["tcp", "udp"], default="tcp", help="Transport protocol (default: tcp)")
    grp.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10)")


def add_auth_args(parser: argparse.ArgumentParser) -> None:
    """Add authentication flags (NTLM or Kerberos)."""
    grp = parser.add_argument_group("authentication (for LDAP and TGS requests)")
    grp.add_argument("-u", "--user", metavar="USER", help="Username (sAMAccountName)")
    grp.add_argument("-p", "--password", metavar="PASS", help="Cleartext password")
    grp.add_argument("-H", "--hashes", metavar="HASH", help="NTLM hash - LM:NT, :NT, or NT")
    grp.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos auth via ccache (obtain with kw-tgt)")
    grp.add_argument("-c", "--ccache", metavar="FILE", help="CCache file with TGT (for -k)")


def add_key_args(parser: argparse.ArgumentParser) -> None:
    """Add per-etype key flags (for kw-tgt pass-the-key only)."""
    grp = parser.add_argument_group("kerberos keys (pass-the-key)")
    grp.add_argument("--rc4-key", metavar="HEX", help="RC4 key / NT hash (32 hex chars)")
    grp.add_argument("--aes128-key", metavar="HEX", help="AES-128 key (32 hex chars)")
    grp.add_argument("--aes256-key", metavar="HEX", help="AES-256 key (64 hex chars)")
    grp.add_argument("--des-md5-key", metavar="HEX", help="DES-CBC-MD5 key (16 hex chars)")
    grp.add_argument("--des-crc-key", metavar="HEX", help="DES-CBC-CRC key (16 hex chars)")


def add_target_args(parser: argparse.ArgumentParser, *, metavar: str = "TARGET") -> None:
    """Add no-auth target flags (``-t``, ``-T``)."""
    grp = parser.add_argument_group("targets (no authentication required)")
    grp.add_argument("-t", "--target", action="append", metavar=metavar, help=f"{metavar} to attack (repeatable)")
    grp.add_argument("-T", "--targets-file", metavar="FILE", help=f"File with {metavar}s, one per line")


def add_ldap_args(parser: argparse.ArgumentParser) -> None:
    """Add LDAP discovery flags (requires authentication)."""
    grp = parser.add_argument_group("LDAP discovery (requires -u/-p or -k)")
    grp.add_argument("--ldap", action="store_true", help="Query LDAP for roastable accounts")
    grp.add_argument("--ldap-all", action="store_true", help="Query LDAP for all users and try each (spray)")
    grp.add_argument("--ldap-ssl", action="store_true", help="Use LDAPS (port 636)")


def add_output_args(parser: argparse.ArgumentParser, *, enctype: bool = True) -> None:
    """Add output flags."""
    grp = parser.add_argument_group("output")
    if enctype:
        grp.add_argument("-e", "--enctype", choices=_ETYPE_CHOICES, default="rc4", help="Encryption type (default: rc4)")
    grp.add_argument("-o", "--output", metavar="FILE", help="Write hashes to file")
    grp.add_argument("--format", choices=["hashcat", "john"], default="hashcat", dest="hash_format", help="Hash output format (default: hashcat)")


# ---------------------------------------------------------------------------
# Context resolution (single entry point for all CLI tools)
# ---------------------------------------------------------------------------


def resolve_context(args: argparse.Namespace, logger: Logger) -> KerberosContext:
    """Resolve the full Kerberos context from CLI args, ccache, and DNS.

    Populates domain, username, DC IP, and DC hostname in one step.

    Resolution chain:
    1. Domain/user from ccache (``-k -c``) or ``-d``/``-u`` flags
    2. DC via DNS SRV (gives both hostname and IP - most reliable)
    3. ``--dc-ip`` overrides IP, ``--dc-hostname`` overrides hostname
    4. Domain A/AAAA as last resort for IP
    """
    # -- Step 1: Domain and username ----------------------------------------
    domain = args.domain
    username = getattr(args, "user", None)
    use_kerberos = getattr(args, "kerberos", False)
    ccache_path = getattr(args, "ccache", None) or _env_ccache()

    if ccache_path and not use_kerberos:
        logger.warning("-c/--ccache provided without -k/--kerberos. Add -k to use Kerberos auth.")

    if use_kerberos and ccache_path:
        try:
            ccache_user, ccache_domain = get_ccache_info(ccache_path)
            domain = domain or ccache_domain
            username = username or ccache_user
            logger.verbose("Ccache: %s@%s", ccache_user, ccache_domain.upper())
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to read ccache: %s", exc)  # noqa: TRY400
            sys.exit(1)

    if not domain:
        logger.error("-d/--domain is required (or use -k -c to auto-detect from ccache).")
        sys.exit(1)

    # Write back so downstream code (build_credential, etc.) sees them.
    args.domain = domain
    if username:
        args.user = username

    # -- Step 2: SRV lookup first (gives hostname + IP) ---------------------
    dc_ip: str | None = None
    dc_hostname: str | None = None

    srv_target = resolve_srv(f"_kerberos._tcp.{domain}")
    if srv_target:
        srv_ip = resolve_host(srv_target)
        if srv_ip:
            dc_ip, dc_hostname = srv_ip, srv_target
            logger.verbose("SRV: %s → %s (%s)", domain, dc_hostname, dc_ip)

    # -- Step 3: Explicit flags override/supplement -------------------------
    dc_ip_arg = getattr(args, "dc_ip", None)
    dc_hostname_arg = getattr(args, "dc_hostname", None)

    if dc_ip_arg:
        if is_ip(dc_ip_arg):
            dc_ip = dc_ip_arg
            logger.debug("--dc-ip: using IP %s directly", dc_ip_arg)
        else:
            dc_hostname = dc_ip_arg
            resolved = resolve_host(dc_ip_arg)
            if resolved:
                dc_ip = resolved
                logger.verbose("--dc-ip: resolved %s → %s", dc_ip_arg, resolved)
            elif not dc_ip:
                logger.error("Cannot resolve --dc-ip hostname '%s'.", dc_ip_arg)
                sys.exit(1)

    if dc_hostname_arg:
        dc_hostname = dc_hostname_arg
        logger.debug("--dc-hostname: %s", dc_hostname_arg)

    # -- Step 4: Last resort - domain A/AAAA --------------------------------
    if not dc_ip:
        dc_ip = resolve_host(domain)
        if dc_ip:
            logger.verbose("DNS A/AAAA: %s → %s", domain, dc_ip)

    if not dc_ip:
        logger.error("Cannot resolve DC for '%s'.  Use --dc-ip.", domain)
        sys.exit(1)

    logger.verbose("Context: domain=%s dc=%s hostname=%s user=%s", domain, dc_ip, dc_hostname or "-", username or "-")

    return KerberosContext(
        domain=domain,
        realm=domain.upper(),
        dc_ip=dc_ip,
        dc_hostname=dc_hostname,
        username=username,
        timeout=getattr(args, "timeout", 10.0),
    )


def _env_ccache() -> str | None:
    """Return ``KRB5CCNAME`` env var if set, else ``None``."""
    import os  # noqa: PLC0415

    return os.environ.get("KRB5CCNAME") or None


# ---------------------------------------------------------------------------
# Credential / hash parsing
# ---------------------------------------------------------------------------


def parse_nthash(raw: str) -> bytes:
    """Parse NTLM hash from ``LM:NT``, ``:NT``, or ``NT`` format."""
    raw = raw.strip()
    nt_hex = raw.split(":")[-1] if ":" in raw else raw
    return bytes.fromhex(nt_hex)


def build_credential(args: argparse.Namespace, *, require_user: bool = True) -> KerberosCredential:
    """Build a ``KerberosCredential`` from CLI auth args (-u, -p, -H)."""
    if require_user and not args.user:
        print("Error: -u/--user is required.", file=sys.stderr)
        sys.exit(1)

    nthash = parse_nthash(args.hashes) if args.hashes else b""

    return KerberosCredential(
        username=args.user or "",
        domain=args.domain,
        password=args.password,
        nthash=nthash,
    )


def build_credential_full(args: argparse.Namespace) -> KerberosCredential:
    """Build a ``KerberosCredential`` with all key types (for kw-tgt)."""
    cred = build_credential(args)

    if hasattr(args, "rc4_key") and args.rc4_key:
        cred.nthash = bytes.fromhex(args.rc4_key)
    if hasattr(args, "aes128_key") and args.aes128_key:
        cred.aes128_key = bytes.fromhex(args.aes128_key)
    if hasattr(args, "aes256_key") and args.aes256_key:
        cred.aes256_key = bytes.fromhex(args.aes256_key)

    des_hex = getattr(args, "des_md5_key", None) or getattr(args, "des_crc_key", None)
    if des_hex:
        cred.des_key = bytes.fromhex(des_hex)

    return cred


# ---------------------------------------------------------------------------
# LDAP connection helper
# ---------------------------------------------------------------------------


def ldap_connect_from_args(args: argparse.Namespace, logger: Logger, ctx: KerberosContext) -> ldap3.Connection:
    """Connect to LDAP using CLI auth args and resolved context."""
    if not args.user and not getattr(args, "kerberos", False):
        logger.error("LDAP modes require -u/--user (NTLM) or -k (Kerberos).")
        sys.exit(1)
    if not getattr(args, "kerberos", False) and not args.password and not args.hashes:
        logger.error("LDAP NTLM auth requires -p/--password or -H/--hashes.")
        sys.exit(1)

    nthash = ""
    if args.hashes and not args.password:
        nthash = parse_nthash(args.hashes).hex()

    use_ssl = getattr(args, "ldap_ssl", False)
    use_kerberos = getattr(args, "kerberos", False)
    ccache = getattr(args, "ccache", None)

    try:
        return connect(
            ctx.dc_ip,
            ctx.domain,
            username=args.user or "",
            password=args.password or "",
            nthash=nthash,
            use_ssl=use_ssl,
            use_kerberos=use_kerberos,
            ccache=ccache,
            dc_hostname=ctx.dc_hostname,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("LDAP connection failed: %s", exc)  # noqa: TRY400
        sys.exit(1)


def ldap_discover_all_users(args: argparse.Namespace, logger: Logger, ctx: KerberosContext) -> list[str]:
    """LDAP: enumerate all enabled user accounts.  Shared by ``--ldap-all``."""
    conn = ldap_connect_from_args(args, logger, ctx)

    logger.info("LDAP: enumerating all users in %s", args.domain)
    usernames = find_all_users(conn, args.domain)
    logger.info("LDAP: found %d users to spray", len(usernames))
    conn.unbind()
    return usernames


# ---------------------------------------------------------------------------
# Target collection
# ---------------------------------------------------------------------------


def collect_targets(args: argparse.Namespace) -> list[str]:
    """Gather targets from ``-t`` and ``-T`` flags."""
    targets: list[str] = []
    if args.target:
        targets.extend(args.target)
    if args.targets_file:
        for line in Path(args.targets_file).read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                targets.append(stripped)
    return targets


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def print_header(prog: str, fields: list[tuple[str, str]]) -> None:
    """Print a structured CLI header to *stderr* (same stream as the logger).

    Args:
        prog: Tool name (e.g. ``kw-roast``).
        fields: List of ``(label, value)`` pairs to display.

    """
    parts = [f"{prog} v{__version__}", ""]
    width = max(len(label) for label, _ in fields) if fields else 0
    for label, value in fields:
        parts.append(f"  {label:<{width}} : {value}")
    parts.append("")
    print("\n".join(parts), file=sys.stderr)


def safe_output_path(path: str) -> Path:
    """Return a non-conflicting output path, appending ``_1``, ``_2``, etc. if the file exists.

    Example: ``hashes.txt`` → ``hashes_1.txt`` → ``hashes_2.txt``
    """
    p = Path(path)
    if not p.exists():
        return p

    stem = p.stem
    suffix = p.suffix
    parent = p.parent
    counter = 1
    while True:
        candidate = parent / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def output_results(results: list[RoastResult], output: str | None, logger: Logger) -> None:
    """Print results to stdout and optionally write to file."""
    if not results:
        logger.warning("No hashes obtained.")
        return

    lines = [r.hash_string for r in results]
    for line in lines:
        print(line)

    if output:
        out_path = safe_output_path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(lines) + "\n")
        logger.success("Wrote %d hash(es) to %s", len(lines), out_path)
    else:
        logger.success("Extracted %d hash(es)", len(lines))

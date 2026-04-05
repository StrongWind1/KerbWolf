"""CLI entry point for ``kw-tgt`` - request a TGT with any credential type."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from kerbwolf import __version__
from kerbwolf.attacks.gettgt import get_tgt
from kerbwolf.cli._common import build_credential_full, print_header, resolve_context
from kerbwolf.log import Logger
from kerbwolf.models import ETYPE_BY_NAME, KerbWolfError, TransportProtocol

# Map key flags to their implied etype.
_KEY_ETYPE_MAP = {
    "rc4_key": "rc4",
    "aes128_key": "aes128",
    "aes256_key": "aes256",
    "des_md5_key": "des-cbc-md5",
    "des_crc_key": "des-cbc-crc",
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kw-tgt",
        description="Request a Kerberos TGT using password, hash, or key (pass-the-key).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")

    # -- target (required) --
    grp = parser.add_argument_group("target (required)")
    grp.add_argument("-d", "--domain", required=True, help="Domain FQDN")
    grp.add_argument("-u", "--user", required=True, metavar="USER", help="Username (sAMAccountName)")

    # -- credential (one required, mutually exclusive) --
    cred_grp = parser.add_argument_group("credential (one required)")
    cred_mx = cred_grp.add_mutually_exclusive_group(required=True)
    cred_mx.add_argument("-p", "--password", metavar="PASS", help="Cleartext password")
    cred_mx.add_argument("-H", "--hashes", metavar="HASH", help="NTLM hash - LM:NT, :NT, or NT (implies -e rc4)")
    cred_mx.add_argument("--rc4-key", metavar="HEX", help="RC4 key / NT hash - 32 hex (implies -e rc4)")
    cred_mx.add_argument("--aes256-key", metavar="HEX", help="AES-256 key - 64 hex (implies -e aes256)")
    cred_mx.add_argument("--aes128-key", metavar="HEX", help="AES-128 key - 32 hex (implies -e aes128)")
    cred_mx.add_argument("--des-md5-key", metavar="HEX", help="DES-CBC-MD5 key - 16 hex (implies -e des-cbc-md5)")
    cred_mx.add_argument("--des-crc-key", metavar="HEX", help="DES-CBC-CRC key - 16 hex (implies -e des-cbc-crc)")

    # -- connection --
    grp = parser.add_argument_group("connection")
    grp.add_argument("--dc-ip", metavar="IP", help="DC IP or hostname (resolved via DNS SRV if omitted)")
    grp.add_argument("--dc-hostname", metavar="HOST", help="DC FQDN for Kerberos SPN (auto-detected if omitted)")
    grp.add_argument("--transport", choices=["tcp", "udp"], default="tcp", help="Transport protocol (default: tcp)")
    grp.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10)")

    # -- output --
    grp = parser.add_argument_group("output")
    grp.add_argument("-e", "--enctype", choices=["des-cbc-crc", "des-cbc-md5", "rc4", "aes128", "aes256"], default=None, help="Encryption type (auto-detected from key, default: rc4)")
    grp.add_argument("-o", "--output", metavar="FILE", help="Output ccache file (default: <user>.ccache)")

    return parser


def _resolve_enctype(args: argparse.Namespace, logger: Logger) -> str:
    """Determine the encryption type from credentials.

    Keys and hashes have a fixed etype - ``-e`` is ignored if a key is provided.
    ``-e`` only applies to password auth (selects the key derivation method).
    """
    # Key flags have a fixed etype - -e is irrelevant.
    for key_attr, etype_name in _KEY_ETYPE_MAP.items():
        if getattr(args, key_attr, None):
            if args.enctype and args.enctype != etype_name:
                logger.warning("-e %s ignored - %s implies etype %s.", args.enctype, key_attr.replace("_", "-"), etype_name)
            return etype_name

    # -H implies RC4 (NT hash IS the RC4 key).
    if args.hashes:
        if args.enctype and args.enctype != "rc4":
            logger.warning("-e %s ignored - NT hash implies etype rc4.", args.enctype)
        return "rc4"

    # Password - -e selects derivation method (default: rc4).
    return args.enctype or "rc4"


def main(argv: list[str] | None = None) -> None:
    """Entry point for ``kw-tgt``."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    logger = Logger(args.verbose)

    # Resolve enctype (auto-detect from key or use default).
    args.enctype = _resolve_enctype(args, logger)

    ctx = resolve_context(args, logger)
    cred = build_credential_full(args)
    etype = ETYPE_BY_NAME[args.enctype]
    transport = TransportProtocol(args.transport)
    output_path = args.output or f"{args.user}.ccache"

    # -- header --
    secret = "password" if args.password else "nt_hash" if args.hashes else "key" if any(getattr(args, k, None) for k in _KEY_ETYPE_MAP) else "-"
    print_header(
        "kw-tgt",
        [
            ("Domain", ctx.domain),
            ("DC", f"{ctx.dc_hostname} ({ctx.dc_ip})" if ctx.dc_hostname else ctx.dc_ip),
            ("User", ctx.username or "-"),
            ("Secret", secret),
            ("Etype", etype.name),
            ("Transport", transport.value),
            ("Output", output_path),
        ],
    )

    logger.info("Requesting TGT for %s@%s (etype: %s)", args.user, ctx.realm, etype.name)

    try:
        ccache_bytes, session_key = get_tgt(cred, dc_ip=ctx.dc_ip, etype=etype, transport=transport, timeout=ctx.timeout)
    except KerbWolfError as exc:
        logger.error("%s", exc)  # noqa: TRY400
        sys.exit(1)
    except Exception:
        logger.exception("Unexpected error")
        sys.exit(1)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_bytes(ccache_bytes)
    logger.success("TGT saved to %s", output_path)
    logger.verbose("Session key type: %s", session_key.enctype)


if __name__ == "__main__":
    main()

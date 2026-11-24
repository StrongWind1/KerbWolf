<h1 align="center">KerbWolf</h1>

<p align="center"><strong>Kerberoast, AS-REP roast, and Timeroast from one tool, or pull the same hashes out of a pcap.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/KerbWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/KerbWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/kerbwolf/"><img src="https://img.shields.io/pypi/v/kerbwolf.svg" alt="PyPI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/KerbWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind.dev/KerbWolf/getting-started/installation/">Installation</a> &bull;
  <a href="https://strongwind.dev/KerbWolf/#quick-start">Quick start</a> &bull;
  <a href="https://strongwind.dev/KerbWolf/commands/kw-roast/">Commands</a> &bull;
  <a href="https://strongwind.dev/KerbWolf/guide/hashcat-modes/">Hash reference</a> &bull;
  <a href="https://strongwind.dev/KerbWolf/">Documentation</a>
</p>

---

KerbWolf extracts crackable hashes from Active Directory. It Kerberoasts and AS-REP roasts over the network, Timeroasts computer, gMSA, and trust accounts over MS-SNTP without credentials, and pulls Kerberos, SNTP, and NTLM hashes out of packet captures. One tool covers all four attacks across the 7 Windows Kerberos encryption types, including RFC 8009 AES-SHA2.

## Example

Kerberoast every SPN account discovered over LDAP and write hashcat-ready hashes:

```console
$ kw-roast -k -c admin.ccache --ldap -o hashes.txt
$krb5tgs$23$sql_svc$CORP.LOCAL$<checksum>$<edata2>
$krb5tgs$18$backup_svc$CORP.LOCAL$<checksum>$<edata2>
```

## Features

- **Four attacks**: TGS-REP Roast (Kerberoast), AS-REP Roast, AS-REQ pre-auth from captures (passive), and Timeroasting (unauthenticated MS-SNTP, only a valid RID needed).
- **All 7 encryption types**: DES-CBC-CRC, DES-CBC-MD5, RC4, AES128, and AES256 are requested live with `-e`; AES-SHA2 (etypes 19 and 20) comes from captures. hashcat has no mode for 19 and 20; KerbWolf still writes them in the canonical layout.
- **25 hash formats**: 21 Kerberos, 2 MS-SNTP, and 2 NTLM (Net-NTLMv1 mode 5500, Net-NTLMv2 mode 5600).
- **LDAP discovery**: find SPN accounts, accounts without pre-authentication, and timeroastable computer and gMSA accounts, or spray every enabled user with `--ldap-all`.
- **Every auth method**: password, NT hash, or ccache, with domain and username read from the ccache; `kw-tgt` also takes per-etype keys (pass-the-key).
- **Pcap extraction**: Kerberos AS-REQ, AS-REP, and TGS-REP, plus service tickets from AP-REQs carried by SMB, HTTP, LDAP and DCE-RPC; SNTP timeroast responses; NTLMv1, NTLMv1-ESS, NTLMv2, and LMv2 from 9 transports, with TCP stream reassembly and Type 2/Type 3 pairing; LDAP simple-bind credentials.
- **Timeroast output**: 68-byte MD5 (hashcat 31300) and 120-byte KDF+HMAC-SHA512 formats, current or previous password for the 68-byte format, and a cracking wordlist built from account names.
- **DC resolution and transport**: DNS SRV lookup with A/AAAA fallback, and TCP or UDP with automatic fallback to TCP when a reply is too large.

## Installation

Install from [PyPI](https://pypi.org/project/kerbwolf/):

```sh
uv tool install kerbwolf        # recommended
pip install kerbwolf             # or with pip
```

Or install from source:

```sh
uv tool install git+https://github.com/StrongWind1/KerbWolf
```

See the [installation guide](https://strongwind.dev/KerbWolf/getting-started/installation/) for the system Kerberos libraries, development setup, and dependencies.

## Quick start

```sh
# Get a TGT
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!' -o admin.ccache

# Kerberoast via LDAP auto-discovery
kw-roast -k -c admin.ccache --ldap

# AS-REP Roast
kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -t jsmith

# Timeroast a RID range (no auth)
kw-timeroast 10.0.0.1 -r 500-5000 -o hashes.txt

# Extract everything from a capture
kw-extract capture.pcap -o hashes.txt

# Pipe from tcpdump
tcpdump -i eth0 -w - 'port 88 or port 123 or port 445' | kw-extract -
```

## Commands

| Command | Attack | Auth required |
| --- | --- | --- |
| [`kw-roast`](https://strongwind.dev/KerbWolf/commands/kw-roast/) | TGS-REP Roast (Kerberoast) | Yes (password, hash, or ccache) |
| [`kw-asrep`](https://strongwind.dev/KerbWolf/commands/kw-asrep/) | AS-REP Roast | No (LDAP discovery needs auth) |
| [`kw-tgt`](https://strongwind.dev/KerbWolf/commands/kw-tgt/) | TGT acquisition (pass-the-key) | Yes |
| [`kw-timeroast`](https://strongwind.dev/KerbWolf/commands/kw-timeroast/) | Timeroasting (MS-SNTP) | No (LDAP discovery needs auth) |
| [`kw-extract`](https://strongwind.dev/KerbWolf/commands/kw-extract/) | All, from pcap/pcapng | No (offline) |

The hashcat mode for every attack and etype is in the [mode matrix](https://strongwind.dev/KerbWolf/guide/hashcat-modes/#mode-matrix), the two timeroast formats in the [timeroasting matrix](https://strongwind.dev/KerbWolf/guide/#timeroasting-matrix), AES-SHA2 key derivation in [Encryption types](https://strongwind.dev/KerbWolf/guide/encryption-types/), and the NTLM transports and ports in [kw-extract](https://strongwind.dev/KerbWolf/commands/kw-extract/#ntlm-details).

## Development

```sh
git clone https://github.com/StrongWind1/KerbWolf.git && cd KerbWolf
uv sync                        # install dev dependencies
make check                     # lint, typecheck, tests, strict docs build
```

`make docs` builds the documentation, `make format` auto-fixes formatting, and `make build` builds the wheel and sdist.

## Credits

Built on [Impacket](https://github.com/fortra/impacket) and [ldap3](https://github.com/cannatag/ldap3). Inspired by [Rubeus](https://github.com/GhostPack/Rubeus), [GetUserSPNs.py](https://github.com/fortra/impacket), and [hashcat](https://hashcat.net/).

## Related tools

- [**CredWolf**](https://github.com/StrongWind1/CredWolf): Validate AD passwords, hashes, keys, and tickets over NTLM and Kerberos
- [**NTDSWolf**](https://github.com/StrongWind1/NTDSWolf): Offline NTDS.dit parser and credential extractor for NT/LM hashes, Kerberos keys, LAPS, and gMSA
- [**PassWolf**](https://github.com/StrongWind1/PassWolf): Spec-compliant AD password change, reset, and policy read over SAMR, Netlogon, LSA, Kerberos, LDAP
- [**AD-SecretGen**](https://github.com/StrongWind1/AD-SecretGen): Derive every password-derived AD secret (NT/LM, Kerberos keys, WDigest) from a password
- [**ntcompress**](https://github.com/StrongWind1/ntcompress): Pure-Python ESE record compression and ntdll RtlCompressBuffer/RtlDecompressBuffer formats
- [**Kerberos**](https://github.com/StrongWind1/Kerberos): Protocol internals, security configuration, and attack techniques for Kerberos in Active Directory

All tools: [strongwind.dev](https://strongwind.dev)

## Disclaimer

KerbWolf is for authorized security testing, research, and education. Use it only against systems and data you own or have written permission to test. You are responsible for how you use it.

## License

[Apache License 2.0](LICENSE)

The vendored copy of [ldap3](https://github.com/cannatag/ldap3) in `kerbwolf/_vendor/ldap3/` is by Giovanni Cannata and is licensed under the GNU LGPL v3 or later (see `kerbwolf/_vendor/ldap3/COPYING.LESSER.txt`).

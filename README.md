<p align="center">
  <a href="https://github.com/StrongWind1/KerbWolf"><img src="https://raw.githubusercontent.com/StrongWind1/KerbWolf/main/docs/assets/kerbwolf_banner.png" alt="KerbWolf" width="800"></a>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg" alt="Python 3.11+"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://strongwind1.github.io/KerbWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind1.github.io/KerbWolf/guide/">Guide</a> &bull;
  <a href="https://strongwind1.github.io/KerbWolf/getting-started/installation/">Installation</a> &bull;
  <a href="https://strongwind1.github.io/KerbWolf/commands/kw-roast/">Commands</a>
</p>

Kerberos roasting and hash extraction toolkit for Active Directory.

1. **Kerberos roasting** - extract crackable hashes from Kerberos authentication
2. **Timeroasting** - unauthenticated MS-SNTP hash extraction for computer and gMSA accounts
3. **Pcap extraction** - offline Kerberos, NTLM, and SNTP hash extraction from network captures

> **Warning:** This tool is intended for authorized security testing only. You must have explicit written permission from the system owner before attacking any Active Directory environment.

## Kerberos Roasting

Request encrypted tickets from domain controllers and crack them offline. Supports all 5 Windows encryption types.

| Command | Attack | Auth required |
|---------|--------|---------------|
| `kw-roast` | TGS-REP Roast (Kerberoast) | Yes (password, hash, or ccache) |
| `kw-asrep` | AS-REP Roast | No (LDAP discovery needs auth) |
| `kw-tgt` | TGT acquisition (pass-the-key) | Yes |

```bash
# Get a TGT
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!' -o admin.ccache

# Kerberoast via LDAP auto-discovery
kw-roast -k -c admin.ccache --ldap

# AS-REP Roast
kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -t jsmith
```

**Features:** LDAP enumeration, hashcat + John output, all 5 etypes (DES/RC4/AES128/AES256), ccache auto-detection, DNS SRV resolution, TCP/UDP with auto-fallback.

## Timeroasting

Extract password-equivalent hashes from domain controllers via MS-SNTP. No authentication needed - just a valid RID.

| Command | Auth required |
|---------|---------------|
| `kw-timeroast` | No (LDAP discovery needs auth) |

```bash
# Blind RID scan (no auth)
kw-timeroast 10.0.0.1 -r 500-5000 -o hashes.txt

# LDAP discovery + cracking wordlist
kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -u admin -p 'Pass!' --wordlist crack.txt
```

**Features:** 68-byte MD5 (hashcat 31300) + 120-byte KDF+HMAC-SHA512, current/previous password selection, LDAP discovery of computer + gMSA accounts, cracking wordlist output.

## Pcap Extraction

Extract all crackable hashes from network captures. One tool, all protocols.

| Command | What it extracts |
|---------|-----------------|
| `kw-extract` | Kerberos (AS-REQ, AS-REP, TGS-REP), SNTP (timeroast), NTLM (NTLMv1, NTLMv1-ESS, NTLMv2, LMv2) |

```bash
# Extract everything from a capture
kw-extract capture.pcap -o hashes.txt

# Pipe from tcpdump
tcpdump -i eth0 -w - 'port 88 or port 123 or port 445' | kw-extract -
```

**Kerberos** (port 88): AS-REQ pre-auth timestamps, AS-REP encrypted parts, TGS-REP service tickets. All 5 etypes, 15 hash formats.

**SNTP** (port 123): 68-byte MD5 and 120-byte KDF+HMAC-SHA512 timeroast responses.

**NTLM** (8 transports): Extracts NTLMv1, NTLMv1-ESS, NTLMv2, and LMv2 hashes with automatic TCP stream reassembly and Type 2/Type 3 connection tracking.

| Transport | Ports | Spec |
|-----------|-------|------|
| SMB | 445, 139 | [MS-SMB], [MS-SMB2] |
| HTTP | 80 | [MS-NTHT] |
| WinRM | 5985, 5986 | [MS-WSMV] |
| LDAP | 389 | SASL/SPNEGO |
| SMTP | 25, 587 | [MS-SMTPNTLM] |
| POP3 | 110 | [MS-POP3] |
| IMAP | 143 | [MS-OXIMAP] |
| Telnet | 23 | [MS-TNAP] |

## Attack Matrix

### Kerberos (15 hash types)

|  | DES-CBC-CRC (1) | DES-CBC-MD5 (3) | AES128 (17) | AES256 (18) | RC4 (23) |
|---|---|---|---|---|---|
| **AS-REQ** | `$krb5pa$1$` | `$krb5pa$3$` | `$krb5pa$17$` (19800) | `$krb5pa$18$` (19900) | `$krb5pa$23$` (7500) |
| **AS-REP** | `$krb5asrep$1$` | `$krb5asrep$3$` | `$krb5asrep$17$` (32100) | `$krb5asrep$18$` (32200) | `$krb5asrep$23$` (18200) |
| **TGS-REP** | `$krb5tgs$1$` | `$krb5tgs$3$` | `$krb5tgs$17$` (19600) | `$krb5tgs$18$` (19700) | `$krb5tgs$23$` (13100) |

Numbers in parentheses are hashcat mode numbers. The 9 RC4/AES modes work in hashcat and John today.

### Timeroasting (MS-SNTP)

| Format | Algorithm | Hashcat mode |
|--------|-----------|-------------|
| 68-byte Authenticator | `MD5(NTOWFv1 \|\| salt)` | 31300 |
| 120-byte ExtendedAuth | KDF(SP800-108, HMAC-SHA512) | proposed |

### NTLM (from pcap)

| Type | Hashcat mode |
|------|-------------|
| Net-NTLMv1 / NTLMv1-ESS | 5500 |
| Net-NTLMv2 / LMv2 | 5600 |

## Installation

```bash
pip install .
# or
uv tool install .
```

See the [installation guide](docs/getting-started/installation.md) for development setup and dependencies.

## Development

```bash
git clone https://github.com/StrongWind1/KerbWolf.git
cd kerbwolf
uv sync                        # install dev dependencies
make check                     # run lint + typecheck + tests
make docs                      # build documentation
make format                    # auto-fix formatting
make build                     # build wheel (runs check + docs first)
```

## Disclaimer

KerbWolf is intended for authorized penetration testing, red team engagements, and security audits only. You must have explicit written permission from the system owner before attacking any Active Directory environment. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse or damage caused by this tool.

## Credits

Built on [Impacket](https://github.com/fortra/impacket) and [ldap3](https://github.com/cannatag/ldap3). Inspired by [Rubeus](https://github.com/GhostPack/Rubeus), [GetUserSPNs.py](https://github.com/fortra/impacket), and [hashcat](https://hashcat.net/).

## License

[Apache License 2.0](LICENSE)

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg" alt="Python 3.11+"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
</p>

# KerbWolf

Kerberos roasting and TGT attack toolkit for Active Directory.

KerbWolf extracts crackable hashes from Active Directory. 7 Kerberos encryption types (including RFC 8009 AES-SHA2), 4 attack types, 25 output formats including NTLM. hashcat has a mode for 18 of them; the six AES-SHA2 formats and the 120-byte MS-SNTP format have none.

**[Read the Guide](guide/index.md)**

## Features

- **All 7 encryption types** — DES-CBC-CRC (1), DES-CBC-MD5 (3), RC4-HMAC (23), AES128-SHA1 (17), AES256-SHA1 (18), AES128-SHA2 (19), AES256-SHA2 (20). The live tools request the first five with `-e`; the two AES-SHA2 types are extracted from captures
- **4 attack types** — TGS-REP Roast (Kerberoast), AS-REP Roast, AS-REQ Pre-Auth, Timeroasting (MS-SNTP)
- **25 hash formats** — 21 Kerberos + 2 MS-SNTP + 2 NTLM (NTLMv1 mode 5500, NTLMv2 mode 5600)
- **LDAP enumeration** — auto-discover roastable accounts with paged search, or spray all domain users
- **Every auth method** — password, NT hash (`LM:NT`, `:NT`, `NT`), Kerberos ccache (pass-the-ticket), per-etype keys (pass-the-key, `kw-tgt`)
- **Ccache auto-detection** — in `kw-roast` and `kw-asrep`, `-d` and `-u` are optional when using `-k -c` (domain and username extracted from ccache)
- **Hashcat-ready output** — every hash is written in the layout hashcat's modes load
- **Native pcap parsing** — extract Kerberos, SNTP, and NTLM hashes and LDAP simple-bind passwords from pcap/pcapng captures, with TCP streams reassembled by sequence number
- **NTLM from 9 transports** — SMB, HTTP, WinRM, LDAP, DCE-RPC, SMTP, POP3, IMAP, Telnet
- **IPv4 and IPv6** — for Kerberos requests, DC resolution and pcap parsing; `kw-timeroast` sends over IPv4 only
- **DNS resolution** — SRV (preferred) + A/AAAA fallback for DC discovery
- **TCP and UDP** — configurable Kerberos transport, UDP auto-falls back to TCP when the reply is too large

## Tools

| Command | Attack | Description |
|---------|--------|-------------|
| [`kw-roast`](commands/kw-roast.md) | TGS-REP Roast | Request service tickets and extract hashes (Kerberoast) |
| [`kw-asrep`](commands/kw-asrep.md) | AS-REP Roast | Extract hashes from accounts without pre-authentication |
| [`kw-extract`](commands/kw-extract.md) | All (from pcap) | Extract Kerberos, SNTP, NTLM, and LDAP simple-bind credentials from pcap/pcapng captures |
| [`kw-tgt`](commands/kw-tgt.md) | TGT acquisition | Request a TGT using password, hash, or key (pass-the-key) |
| [`kw-timeroast`](commands/kw-timeroast.md) | Timeroasting (MS-SNTP) | Extract SNTP hashes for computer, gMSA, and trust accounts |

## Quick start

```bash
pip install .

# Kerberoast with LDAP auto-discovery
kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!' --ldap -o tgs.txt

# AS-REP Roast
kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -t jsmith -o asrep.txt

# AS-REQ Pre-Auth (and everything else in a capture)
kw-extract capture.pcap -o capture-hashes.txt

# Crack with hashcat: one mode per hash type and etype
hashcat -m 13100 tgs.txt wordlist.txt      # RC4 TGS-REP
hashcat -m 18200 asrep.txt wordlist.txt    # RC4 AS-REP
```

See the [installation guide](getting-started/installation.md) for setup details, or jump straight to the [guide](guide/index.md).

## Disclaimer

KerbWolf is intended for authorized penetration testing, red team engagements, and security audits only. You must have explicit written permission from the system owner before attacking any Active Directory environment. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse or damage caused by this tool.

## Credits

Built on [Impacket](https://github.com/fortra/impacket) and [ldap3](https://github.com/cannatag/ldap3). Inspired by [Rubeus](https://github.com/GhostPack/Rubeus), [GetUserSPNs.py](https://github.com/fortra/impacket), and [hashcat](https://hashcat.net/).

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)

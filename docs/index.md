<p align="center">
  <img src="assets/kerbwolf_banner.png" alt="KerbWolf" width="800">
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg" alt="Python 3.11+"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
</p>

# KerbWolf

Kerberos roasting and TGT attack toolkit for Active Directory.

KerbWolf extracts crackable hashes from Active Directory. 5 Kerberos encryption types, 4 attack types, 19 hashcat-compatible output formats including NTLM.

**[Read the Guide](guide/index.md)**

## Features

- **All 5 encryption types** — DES-CBC-CRC (1), DES-CBC-MD5 (3), RC4-HMAC (23), AES128 (17), AES256 (18)
- **4 attack types** — TGS-REP Roast (Kerberoast), AS-REP Roast, AS-REQ Pre-Auth, Timeroasting (MS-SNTP)
- **19 hash formats** — 15 Kerberos + 2 MS-SNTP + 2 NTLM (NTLMv1 mode 5500, NTLMv2 mode 5600)
- **LDAP enumeration** — auto-discover roastable accounts with paged search, or spray all domain users
- **Every auth method** — password, NT hash (`LM:NT`, `:NT`, `NT`), Kerberos ccache (pass-the-ticket), per-etype keys (pass-the-key)
- **Ccache auto-detection** — `-d` and `-u` are optional when using `-k -c` (domain and username extracted from ccache)
- **Hashcat + John** — both output formats supported, all 9 RC4/AES modes verified cracking
- **Native pcap parsing** — extract Kerberos, SNTP, and NTLM hashes from pcap/pcapng captures with TCP reassembly
- **NTLM from 8 transports** — SMB, HTTP, WinRM, LDAP, SMTP, POP3, IMAP, Telnet
- **IPv4 and IPv6** — dual-stack support throughout
- **DNS resolution** — SRV (preferred) + A/AAAA fallback for DC discovery
- **TCP and UDP** — configurable transport, UDP auto-falls back to TCP

## Tools

| Command | Attack | Description |
|---------|--------|-------------|
| [`kw-roast`](commands/kw-roast.md) | TGS-REP Roast | Request service tickets and extract hashes (Kerberoast) |
| [`kw-asrep`](commands/kw-asrep.md) | AS-REP Roast | Extract hashes from accounts without pre-authentication |
| [`kw-extract`](commands/kw-extract.md) | All (from pcap) | Extract Kerberos, SNTP, and NTLM hashes from pcap/pcapng captures |
| [`kw-tgt`](commands/kw-tgt.md) | TGT acquisition | Request a TGT using password, hash, or key (pass-the-key) |
| [`kw-timeroast`](commands/kw-timeroast.md) | Timeroasting (MS-SNTP) | Extract SNTP hashes for computer, gMSA, and trust accounts |

## Quick start

```bash
pip install .

# Kerberoast with LDAP auto-discovery
kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!' --ldap

# AS-REP Roast
kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -t jsmith

# AS-REQ Pre-Auth
kw-extract capture.pcap -o hashes.txt

# Crack with hashcat
hashcat -m 13100 hashes.txt wordlist.txt
```

See the [installation guide](getting-started/installation.md) for setup details, or jump straight to the [guide](guide/index.md).

## Disclaimer

KerbWolf is intended for authorized penetration testing, red team engagements, and security audits only. You must have explicit written permission from the system owner before attacking any Active Directory environment. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse or damage caused by this tool.

## Credits

Built on [Impacket](https://github.com/fortra/impacket) and [ldap3](https://github.com/cannatag/ldap3). Inspired by [Rubeus](https://github.com/GhostPack/Rubeus), [GetUserSPNs.py](https://github.com/fortra/impacket), and [hashcat](https://hashcat.net/).

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)

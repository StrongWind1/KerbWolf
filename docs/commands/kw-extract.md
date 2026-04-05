# kw-extract

Extract Kerberos, SNTP (timeroast), and NTLM hashes from pcap and pcapng captures. Completely offline, no network connection or credentials needed.

For a full explanation, see the [guide](../guide/index.md) and [hash formats](../guide/hash-formats.md).

## Help

```
$ kw-extract -h
usage: kw-extract [-h] [--version] [-v] [-o FILE] [--format {hashcat,john}]
                  pcap [pcap ...]

Extract Kerberos, SNTP, and NTLM hashes from pcap/pcapng captures.

positional arguments:
  pcap                  Pcap/pcapng file(s) to parse (use - for stdin)

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Increase verbosity (-v, -vv)
  -o FILE, --output FILE
                        Write hashes to file
  --format {hashcat,john}
                        Hash output format (default: hashcat)

Examples:
  kw-extract capture.pcap
  kw-extract capture.pcapng -o hashes.txt
  kw-extract *.pcap
  tcpdump -i eth0 -w - port 88 | kw-extract -
  tcpdump -i eth0 -w - port 123 | kw-extract -
  tcpdump -i eth0 -w - port 445 | kw-extract -
```

## What it extracts

| Hash type | Source | Protocol | Hashcat mode |
|-----------|--------|----------|-------------|
| `$krb5pa$` | PA-ENC-TIMESTAMP | AS-REQ (port 88) | 7500/19800/19900 |
| `$krb5asrep$` | enc-part (no-preauth accounts) | AS-REP (port 88) | 18200/32100/32200 |
| `$krb5tgs$` | Service ticket enc-part | TGS-REP (port 88) | 13100/19600/19700 |
| `$sntp-ms$` | 68-byte Authenticator (MD5) | MS-SNTP (port 123) | 31300 |
| `$sntp-ms-sha512$` | 120-byte ExtendedAuthenticator | MS-SNTP (port 123) | proposed |
| `user::domain:...` | Net-NTLMv1 / NTLMv1-ESS | NTLM (see below) | 5500 |
| `user::domain:...` | Net-NTLMv2 / LMv2 | NTLM (see below) | 5600 |

Supports: Ethernet, Raw IP, Linux SLL/SLL2, 802.1Q VLAN, IPv4, IPv6, TCP, UDP. TCP streams are reassembled automatically for messages split across multiple segments.

### NTLM details

NTLM authentication spans two packets: the server's Type 2 (CHALLENGE) and the client's Type 3 (AUTHENTICATE). kw-extract tracks TCP connections to pair them automatically. All four NTLM hash types are extracted: NTLMv1, NTLMv1-ESS, NTLMv2, and LMv2 (companion).

Supported transports:

| Protocol | Ports | Spec | Notes |
|----------|-------|------|-------|
| SMB | 445, 139 | [MS-SMB], [MS-SMB2] | NTLMSSP in SESSION_SETUP + raw SMB1 basic security (WordCount=13) |
| HTTP | 80 | [MS-NTHT] | `Authorization: NTLM`, `WWW-Authenticate: NTLM`, `Proxy-*` headers |
| WinRM | 5985, 5986 | [MS-WSMV] | HTTP NTLM on WinRM ports |
| LDAP | 389 | | SASL GSSAPI/SPNEGO bind credentials |
| SMTP | 25, 587 | [MS-SMTPNTLM] | `AUTH NTLM`, `334 <base64>` challenge responses |
| POP3 | 110 | [MS-POP3] | `AUTH NTLM`, `+ <base64>` challenge responses |
| IMAP | 143 | [MS-OXIMAP] | `AUTHENTICATE NTLM`, `+ <base64>` challenge responses |
| Telnet | 23 | [MS-TNAP] | IAC SB AUTH subnegotiation, raw binary NTLM tokens |

## Examples

```bash
# Single file
kw-extract capture.pcap

# Multiple files with output
kw-extract *.pcap -o hashes.txt

# Pipe from tcpdump (live Kerberos capture)
tcpdump -i eth0 -w - port 88 | kw-extract -

# Pipe from tcpdump (live timeroast capture)
tcpdump -i eth0 -w - port 123 | kw-extract -

# Pipe from tcpdump (live NTLM capture)
tcpdump -i eth0 -w - port 445 | kw-extract -

# Capture everything at once
tcpdump -i eth0 -w - 'port 88 or port 123 or port 445' | kw-extract -

# John format
kw-extract capture.pcapng --format john
```

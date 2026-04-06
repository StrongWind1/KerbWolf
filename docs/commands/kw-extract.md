# kw-extract

Extract Kerberos, SNTP (timeroast), NTLM, and LDAP credentials from pcap and pcapng captures. Completely offline, no network connection or credentials needed.

For a full explanation, see the [guide](../guide/index.md) and [hash formats](../guide/hash-formats.md).

## Help

```
$ kw-extract -h
usage: kw-extract [-h] [--version] [-v] [-d DIR] [-o FILE]
                  [--format {hashcat,john}]
                  [pcap ...]

Extract Kerberos, SNTP, NTLM, and LDAP hashes from pcap/pcapng captures.

positional arguments:
  pcap                  Pcap/pcapng file(s) to parse (use - for stdin)

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Increase verbosity (-v, -vv)
  -d DIR, --dir DIR     Recursively scan directory for .pcap/.pcapng files
                        (repeatable)
  -o FILE, --output FILE
                        Write hashes to file
  --format {hashcat,john}
                        Hash output format (default: hashcat)

Examples:
  kw-extract capture.pcap
  kw-extract capture.pcapng -o hashes.txt
  kw-extract *.pcap
  kw-extract -d /pcaps/
  kw-extract -d /pcaps/ -d /more/ -o all.txt
  tcpdump -i eth0 -w - port 88 | kw-extract -
  tcpdump -i eth0 -w - port 123 | kw-extract -
  tcpdump -i eth0 -w - 'port 445 or port 389' | kw-extract -
```

## What it extracts

| Output | Source | Protocol | Hashcat mode |
|--------|--------|----------|-------------|
| `$krb5pa$` | PA-ENC-TIMESTAMP | AS-REQ (port 88) | 7500 / 19800 / 19900 |
| `$krb5asrep$` | enc-part (no-preauth accounts) | AS-REP (port 88) | 18200 / 32100 / 32200 |
| `$krb5tgs$` | Service ticket enc-part | TGS-REP (port 88) | 13100 / 19600 / 19700 |
| `$sntp-ms$` | 68-byte Authenticator (MD5) | MS-SNTP (port 123) | 31300 |
| `$sntp-ms-sha512$` | 120-byte ExtendedAuthenticator | MS-SNTP (port 123) | proposed |
| `user::domain:...` | Net-NTLMv1 / NTLMv1-ESS | NTLM (see below) | 5500 |
| `user::domain:...` | Net-NTLMv2 / LMv2 | NTLM (see below) | 5600 |
| `dn:password` | Simple bind credentials | LDAP (port 389) | cleartext |

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
| DCE-RPC | 135 | [MS-RPCE] §2.2.2.4 | NTLMSSP in auth verifiers on the RPC endpoint mapper port |
| SMTP | 25, 587 | [MS-SMTPNTLM] | `AUTH NTLM`, `334 <base64>` challenge responses |
| POP3 | 110 | [MS-POP3] | `AUTH NTLM`, `+ <base64>` challenge responses |
| IMAP | 143 | [MS-OXIMAP] | `AUTHENTICATE NTLM`, `+ <base64>` challenge responses |
| Telnet | 23 | [MS-TNAP] | IAC SB AUTH subnegotiation, raw binary NTLM tokens |

!!! note "DCE-RPC coverage"
    Port 135 (RPC endpoint mapper) is covered. After a client negotiates an endpoint, the actual RPC calls move to a dynamically-assigned high port — those connections are not covered. NTLM over named pipes (e.g. `\PIPE\lsarpc` on SMB) is already captured via port 445.

### LDAP simple bind

When a client authenticates with a plaintext password (`AuthenticationChoice: simple`), kw-extract extracts the bind DN and password as `dn:password`. Only LDAPv3 simple binds are captured; SASL/SPNEGO binds (used for NTLM and Kerberos) are handled by the NTLM extraction path above.

Output format:

```
cn=admin,dc=corp,dc=local:Password1!
```

## Examples

```bash
# Single file
kw-extract capture.pcap

# Multiple files with output
kw-extract *.pcap -o hashes.txt

# Recursively scan a directory for all pcap files
kw-extract -d /opt/captures/

# Multiple directories
kw-extract -d /pcaps/2025/ -d /pcaps/2026/ -o all.txt

# Mix positional files with a directory scan
kw-extract live.pcap -d /archived/ -o combined.txt

# Pipe from tcpdump (live Kerberos capture)
tcpdump -i eth0 -w - port 88 | kw-extract -

# Pipe from tcpdump (live timeroast capture)
tcpdump -i eth0 -w - port 123 | kw-extract -

# Pipe from tcpdump (live NTLM + LDAP capture)
tcpdump -i eth0 -w - 'port 445 or port 389 or port 135' | kw-extract -

# Capture everything at once
tcpdump -i eth0 -w - 'port 88 or port 123 or port 445 or port 389 or port 135' | kw-extract -

# John format
kw-extract capture.pcapng --format john
```

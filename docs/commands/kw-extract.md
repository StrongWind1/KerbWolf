# kw-extract

Extract Kerberos, SNTP (timeroast), NTLM, and LDAP credentials from pcap and pcapng captures. Completely offline, no network connection or credentials needed.

For a full explanation, see the [guide](../background/attacks.md) and [hash reference](../cracking/hash-reference.md).

## Help

```
$ kw-extract -h
usage: kw-extract [-h] [--version] [-v] [-d DIR] [-o FILE] [pcap ...]

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

| Output | Source | Protocol | Hashcat modes |
|--------|--------|----------|-------------|
| `$krb5pa$` | PA-ENC-TIMESTAMP | AS-REQ (port 88) | 39300 / 39000 / 19800 / 19900 / none / none / 7500 |
| `$krb5asrep$` | enc-part of every AS-REP | AS-REP (port 88) | 39200 / 38600 / 32100 / 32200 / none / none / 18200 |
| `$krb5tgs$` | Service ticket enc-part | TGS-REP (port 88) | 39100 / 38500 / 19600 / 19700 / none / none / 13100 |
| `$krb5tgs$` | Service ticket enc-part | AP-REQ (SMB / HTTP / LDAP / DCE-RPC) | 39100 / 38500 / 19600 / 19700 / none / none / 13100 |
| `$sntp-ms$` | 68-byte Authenticator (MD5) | MS-SNTP (port 123) | 31300 |
| `$sntp-ms-sha512$` | 120-byte ExtendedAuthenticator | MS-SNTP (port 123) | none |
| `user::domain:...` | Net-NTLMv1 / NTLMv1-ESS | NTLM (see below) | 5500 |
| `user::domain:...` | Net-NTLMv2 / LMv2 | NTLM (see below) | 5600 |
| `dn:password` | Simple bind credentials | LDAP (port 389) | cleartext |

The Kerberos modes are listed in etype order 1 / 3 / 17 / 18 / 19 / 20 / 23. hashcat has no mode for etypes 19 and 20, or for the 120-byte MS-SNTP format; those lines are still written.

Supports pcap (microsecond and nanosecond, either byte order) and pcapng files (Enhanced and Simple Packet Blocks, with the link type of each packet's own interface), over Ethernet, Raw IP, Linux SLL/SLL2 and 802.1Q VLAN link layers, with IPv4, IPv6, TCP and UDP.

TCP streams are reassembled by sequence number, so a message split across segments is read whole, and retransmitted or out-of-order segments do not corrupt it. A segment the capture missed cannot be recovered: the message it belonged to is lost.

### Kerberos details

- **Every AS-REP is extracted**, not only the ones for accounts without pre-authentication. The enc-part of a normal, pre-authenticated password logon is encrypted with the same client key, so a capture of ordinary logons yields both a `$krb5pa$` and a `$krb5asrep$` line per user. Smartcard (PKINIT) and FAST-armored logons use a different reply key; their lines are written too but are not password-crackable.
- **Salts seen in the capture fix the user field.** AES and DES keys are salted with the account's real spelling, which is not always what is on the wire. `kw-extract` collects the salt the KDC sends (ETYPE-INFO2 in a `PREAUTH_REQUIRED` error or an AS-REP, PA-PW-SALT in a DES AS-REP) and uses it for the user field of the hashes below. Without a salt it warns and keeps the name from the packet.
- **AS-REQ user field.** The `cname` is what the user typed, in whatever case. A salt for that name replaces it.
- **AS-REP user field.** The username comes from the salt in the reply when there is one, otherwise from the `cname`.
- **TGS-REP user field.** A TGS-REP names the service, not the account that owns it, so the user field is the ticket's `sname`. If the capture holds a salt for that name, the salt supplies the spelling. That is the case for traffic from `kw-roast`, which requests tickets by sAMAccountName. In ordinary Windows traffic the `sname` is an SPN such as `HTTP/web01.corp.local`: an RC4 line cracks as it is, but an AES or DES line will not until the user field is replaced with the name the key is salted with (the sAMAccountName for a user account, `host<fqdn>` for a computer account).
- **AP-REQ service tickets.** A client wraps an AP-REQ in SPNEGO when it authenticates to a service over SMB, HTTP (WinRM/IIS), LDAP or DCE-RPC. The ticket inside is the same one the KDC issued in the TGS-REP, encrypted with the service account's key, so a capture of client-to-service traffic yields Kerberoast material with no port 88 packets. The `sname` and salt behave exactly as for a TGS-REP. A ticket is reported once per capture: from its TGS-REP when that is present, otherwise from the first AP-REQ that carries it. A client replays the same ticket to a service until it expires, so repeats on one connection are dropped.
- **Output.** `-o` never overwrites. If the file exists, the hashes go to `name_1.ext`, then `name_2.ext`, and so on.
- **Piped input.** With `-`, hashes are printed when the capture ends, not as packets arrive. In `tcpdump -w - ... | kw-extract -`, one Ctrl-C stops tcpdump and `kw-extract` reads what is left in the pipe and prints everything; a second Ctrl-C stops it at once and prints what it had read.

### NTLM details

NTLM authentication spans two packets: the server's Type 2 (CHALLENGE) and the client's Type 3 (AUTHENTICATE). kw-extract tracks TCP connections to pair them automatically. A Type 3 whose challenge is not in the capture yields nothing. All four NTLM hash types are extracted: NTLMv1, NTLMv1-ESS, NTLMv2, and LMv2 (companion).

Supported transports:

| Protocol | Ports | Spec | Notes |
|----------|-------|------|-------|
| SMB | 445, 139 | [MS-SMB], [MS-SMB2] | NTLMSSP in SESSION_SETUP (SMB2 and SMB1 extended security), and raw SMB1 basic security: challenge from the NEGOTIATE response, LM/NT responses from SESSION_SETUP (WordCount=13) |
| HTTP | 80 | [MS-NTHT] | `NTLM` and `Negotiate` tokens in the `Authorization`, `WWW-Authenticate` and `Proxy-*` headers; a Kerberos token under `Negotiate` is skipped |
| WinRM | 5985, 5986 | [MS-WSMV] | The same HTTP headers on the WinRM ports; 5986 is normally TLS, and only cleartext HTTP can be read |
| LDAP | 389 | | NTLMSSP tokens in bind requests and responses (SASL GSS-SPNEGO or Sicily); Kerberos binds yield nothing |
| DCE-RPC | 135 | [MS-RPCE] §2.2.2.11 | NTLMSSP in auth verifiers on the RPC endpoint mapper port |
| SMTP | 25, 587 | [MS-SMTPNTLM] | `AUTH NTLM`, `334 <base64>` challenge responses |
| POP3 | 110 | [MS-POP3] | `AUTH NTLM`, `+ <base64>` challenge responses |
| IMAP | 143 | [MS-OXIMAP4] | `AUTHENTICATE NTLM`, `+ <base64>` challenge responses |
| Telnet | 23 | [MS-TNAP] | IAC SB AUTH subnegotiation, raw binary NTLM tokens |

!!! note "DCE-RPC coverage"
    Port 135 (RPC endpoint mapper) is covered. After a client negotiates an endpoint, the actual RPC calls move to a dynamically-assigned high port — those connections are not covered. NTLM over named pipes (e.g. `\PIPE\lsarpc` on SMB) is already captured via port 445.

### LDAP simple bind

When a client authenticates with a plaintext password (`AuthenticationChoice: simple`), kw-extract extracts the bind DN and password as `dn:password`. Only LDAPv3 simple binds are captured. SASL binds that carry NTLM are handled by the NTLM extraction path above; Kerberos binds yield nothing.

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

# Pipe from tcpdump (hashes print when you stop it with Ctrl-C)
tcpdump -i eth0 -w - port 88 | kw-extract -

# Pipe from tcpdump (live timeroast capture)
tcpdump -i eth0 -w - port 123 | kw-extract -

# Pipe from tcpdump (live NTLM + LDAP capture)
tcpdump -i eth0 -w - 'port 445 or port 389 or port 135' | kw-extract -

# Capture everything at once
tcpdump -i eth0 -w - 'port 88 or port 123 or port 445 or port 389 or port 135' | kw-extract -
```

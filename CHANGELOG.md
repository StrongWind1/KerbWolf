# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-04-03

Initial release.

### Added

**5 CLI tools:**

- `kw-roast` -- TGS-REP Roast (Kerberoast) with 3 auth modes: NTLM password/hash, Kerberos ccache, and no-preauth (AS-REQ kerberoasting via DONT_REQ_PREAUTH accounts)
- `kw-asrep` -- AS-REP Roast for accounts without Kerberos pre-authentication
- `kw-tgt` -- TGT acquisition with password, NT hash, or per-etype keys (pass-the-key for RC4, AES128, AES256, DES-CBC-MD5, DES-CBC-CRC)
- `kw-timeroast` -- Timeroasting via MS-SNTP: 68-byte MD5 (hashcat 31300) and 120-byte KDF+HMAC-SHA512 formats, with LDAP discovery, RID range scanning, wordlist generation, and 4-file output split
- `kw-extract` -- Offline pcap/pcapng hash extraction for Kerberos, MS-SNTP, and NTLM

**19 hashcat-compatible hash formats:**

- 15 Kerberos hashes: 3 attacks (AS-REQ, AS-REP, TGS-REP) x 5 encryption types (DES-CBC-CRC, DES-CBC-MD5, RC4-HMAC, AES128, AES256)
- 2 MS-SNTP hashes: `$sntp-ms$` (MD5, mode 31300) and `$sntp-ms-sha512$` (KDF+HMAC-SHA512, proposed)
- 2 NTLM hashes: Net-NTLMv1/NTLMv1-ESS (mode 5500), Net-NTLMv2/LMv2 (mode 5600)

**Pcap extraction (`kw-extract`):**

- Native pcap and pcapng parser (no libpcap dependency)
- Kerberos (port 88): AS-REQ PA-ENC-TIMESTAMP, AS-REP enc-part, TGS-REP ticket enc-part
- MS-SNTP (port 123): 68-byte Authenticator and 120-byte ExtendedAuthenticator responses
- NTLM from 8 transports: SMB (445/139), HTTP (80), WinRM (5985/5986), LDAP (389), SMTP (25/587), POP3 (110), IMAP (143), Telnet (23)
- TCP stream reassembly for messages split across multiple segments
- Connection tracking to pair NTLM Type 2 (challenge) with Type 3 (authenticate)
- Link layers: Ethernet, Raw IP, Linux SLL/SLL2, 802.1Q VLAN
- IPv6 with extension header chain walking

**LDAP enumeration:**

- Paged search for large domains (1000 results per page)
- Kerberoastable accounts (SPN filter), AS-REP roastable accounts (DONT_REQUIRE_PREAUTH), all users (spray), DES-enabled DCs, timeroastable computer/gMSA accounts
- NTLM (password + hash) and Kerberos SASL authentication
- DC hostname auto-detection via RootDSE for GSSAPI SPN construction

**Infrastructure:**

- DNS SRV + A/AAAA resolution for DC discovery
- TCP and UDP transport with UDP-to-TCP fallback (RFC 4120 section 7.2.1)
- IPv4 and IPv6 dual-stack
- Ccache auto-detection: domain and username extracted from ccache principal when using `-k -c`
- Hashcat and John the Ripper output formats

**Timeroasting protocol research:**

- Cracked the 120-byte ExtendedAuthenticator algorithm: SP800-108 KDF with HMAC-SHA512 PRF and null-terminated `"sntp-ms"` label
- Documented 5 spec deviations in MS-SNTP confirmed across Server 2022 and Server 2025
- Confirmed timeroastable account types: computer, gMSA, trust accounts (YES); MSA, dMSA, user (NO)
- Trust account timeroasting: both parent and child trust accounts respond, keep password history

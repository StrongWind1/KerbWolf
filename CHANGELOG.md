# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `kw-extract` reads Kerberos AP-REQ service tickets carried by SMB, HTTP (WinRM/IIS), LDAP and DCE-RPC, so a capture of client-to-service traffic yields Kerberoast hashes with no port 88 packets. A ticket is reported once per capture: from its TGS-REP when present, otherwise from the first AP-REQ that carries it.

### Changed

- Restructured the docs. Pages are grouped as Commands, Cracking, Troubleshooting and Background, and every old page address redirects to its new one. Three pages are new: Common options (credentials, DC resolution, LDAP discovery, `-e`), Troubleshooting (a symptom table, and the rule that the user and realm fields are the salt for AES and DES) and Timeroasting. Command pages open with examples and share one layout. Tables that restated each other were merged and nine redundant diagrams removed; nothing else was dropped.
- The docs install from PyPI, and the remaining diagrams are readable in the light theme.
- Checked the docs against hashcat master (`16b164c15`) and against a Server 2022 domain controller, and corrected what had drifted. Mode 39400 takes a 58-76 hex timestamp, modes 19800 and 19900 an explicit salt of up to 1022 chars, and the no-etype shape of 18200 rejects another etype's joined line. The docs now say that hashcat v8.0.0 does not load the `$user$realm$` layout in modes 7500, 13100, 18200, 19800, 19900, 35300, 35400 and 38500, so those lines need a build from master; that a user field ending in `$` (a machine account) makes hashcat reject a line; that disabled machine accounts do not answer a timeroast request; and that `kw-extract` cannot match a `PREAUTH_REQUIRED` salt to a machine account or read an AP-REQ that lacks the GSS-API header.

## [2.0.0] - 2026-11-15

### Added

- `kw-roast -t user@domain` looks the name up as a `userPrincipalName` in LDAP and requests the ticket for the account that owns it.
- `kw-extract` reads NTLM from HTTP `Negotiate` headers (bare or SPNEGO-wrapped NTLMSSP), which is what WinRM and most IIS sites use.
- `kw-extract` reads SMB1 basic-security logons: the challenge is taken from the NEGOTIATE response.
- `kw-extract` reads pcapng Simple Packet Blocks and uses the link type of each packet's own interface.

### Changed

- `kw-extract -o` no longer overwrites an existing file; like `kw-roast`, `kw-asrep` and `kw-timeroast`, it writes to `name_1.ext`, `name_2.ext` and so on.
- Hashcat mode lookups return 0 for etypes 19 and 20, because hashcat has no mode for AES-SHA2.
- `kw-timeroast` sends the 120-byte request once per RID whatever `--password` is, because that format cannot select the password. Its hashes go to `<name>-sha512.txt` instead of `<name>-current-sha512.txt` and `<name>-previous-sha512.txt`.

### Removed

- John the Ripper output and the `--format {hashcat,john}` option of `kw-roast`, `kw-asrep` and `kw-extract`. Hashes are always written in the hashcat layout. John did not load the lines written for DES hashes.

### Fixed

- `--version` and the banner of every command report the installed package version instead of a hard-coded `1.0.0`.
- `kw-extract` reassembles TCP streams by sequence number. Retransmitted and out-of-order segments used to be appended in capture order and gave a wrong hash without a warning.
- `tcpdump -w - | kw-extract -` prints its hashes when stopped with Ctrl-C. They used to be discarded.
- DES hashes get the account's real spelling in the user field. The KDC sends the salt for DES replies as PA-PW-SALT, which was not read, so a target or logon typed in another case gave a hash that could not crack. This affects `kw-asrep`, `kw-roast` and `kw-extract`.
- `kw-extract` gives AS-REQ pre-auth hashes the account's real spelling when the capture holds the salt for it.
- `kw-roast` reads the salt of `DONT_REQ_PREAUTH` service accounts, so their hashes are no longer written with an unverified name and a warning.
- `kw-timeroast -r 1-` and `-r -` no longer try to build a list of two billion RIDs.

## [1.1.0] - 2026-10-28

### Added

- Native DES-CBC-CRC (etype 1) cipher implementation with CRC-32 checksum per RFC 3961 section 6.
- Native RFC 8009 SHA2 key derivation (PBKDF2-SHA256/SHA384 + KDF-HMAC-SHA2), replacing the stub that aliased SHA1 cipher classes.
- Salt extraction from AS-REP ETYPE-INFO2 padata, enabling TGT acquisition for accounts with DONT_REQUIRE_PREAUTH set.

### Fixed

- Pre-Auth hash format now outputs `$krb5pa$E$user$realm$checksum$encrypted` with separate checksum and encrypted fields, matching hashcat canonical format.
- `kw-tgt` no longer crashes with "Unexpected response when retrieving salt" when the target account has DONT_REQUIRE_PREAUTH (etypes 1, 3, 17).
- Test suite reduced from ~115s to ~1.5s by mocking `_probe_salts` in kerberoast tests (was making real TCP connections to test IPs).

### Removed

- `aes128-sha2` and `aes256-sha2` CLI options from `kw-roast`, `kw-asrep`, and `kw-tgt`. SHA2 etypes remain supported internally for pcap extraction and hash formatting.

## [1.0.0] - 2026-10-27

### Added

- RFC 8009 AES-SHA2 encryption types (etype 19: AES128-CTS-HMAC-SHA256-128, etype 20: AES256-CTS-HMAC-SHA384-192) for all three attack types: TGS-REP roast, AS-REP roast, and TGT acquisition.
- `-e aes128-sha2` and `-e aes256-sha2` etype flags for `kw-roast`, `kw-asrep`, and `kw-tgt`.
- Windows Server 2025 string-to-key implementation: PBKDF2 with 4096 iterations (not RFC 8009 default 32768) + KDF-HMAC-SHA2 second pass with etype name salt prefix.
- 6 new hashcat-compatible hash formats: `$krb5tgs$19/$20`, `$krb5asrep$19/$20`, `$krb5pa$19/$20`.
- Total hash format count: 21 Kerberos + 2 SNTP + 2 NTLM = 25 formats.
- ETYPE-INFO2 salt probing for all non-RC4 hashes. Every AES hash now uses an ETYPE-INFO2-verified salt or warns the user that casing may be wrong. This ensures AES hashes actually crack.
- sAMAccountName-first TGS-REQ: kw-roast now sends the sAMAccountName (not SPN) as the TGS-REQ sname, so the KDC echoes the correct account name and pcap extraction produces crackable hashes.
- SPN-to-sAMAccountName LDAP resolution: manual `-t MSSQLSvc/db01.corp.local` targets are resolved to sAMAccountNames via LDAP before the TGS-REQ.
- KRB-ERROR salt dictionary for pcap extraction: `kw-extract` now correlates KRB-ERROR ETYPE-INFO2 salts with TGS-REP hashes from the same capture.

### Fixed

- TGT etype for kerberoast now auto-negotiates independently of the `-e` attack etype. Previously `-e des-cbc-crc` or `-e aes256-sha2` would fail because the TGT also tried that etype.
- TGT acquisition offers AES256, AES128, and RC4 to the KDC so it picks the strongest it supports, instead of only AES256+RC4.

### Changed

- Consolidated docs: merged `hash-formats.md` into `hashcat-modes.md` as the single hash reference page. Fixed stale hash format examples across all documentation.

### Removed

- `_target_to_display_name()` — extracted hostnames from SPNs (e.g., `sql01` from `MSSQLSvc/sql01.contoso.com:1433`), producing uncrackable AES hashes.
- LDAP casing resolution for AS-REP roast — replaced by ETYPE-INFO2 from AS-REP padata which is always correct.

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

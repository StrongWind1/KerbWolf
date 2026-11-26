# Troubleshooting

A hash will not load, a hash will not crack, or a tool returned nothing. Find what you see in the table and follow the link to where it is explained.

## Symptoms

| What you see | Cause | Explained in |
|---|---|---|
| An AES or DES hash never cracks with a password known to be right | The user field is not the name the key is salted with | [The section below](#the-user-field-is-a-cryptographic-input) |
| The line is etype 19 or 20, or starts `$sntp-ms-sha512$` | hashcat has no mode for it | [Mode matrix](cracking/hash-reference.md#mode-matrix) |
| hashcat does not know modes 39000 through 39400 | They were added after v8.0.0 and need a build from master | [Mode matrix](cracking/hash-reference.md#mode-matrix) |
| hashcat v8.0.0 rejects a KerbWolf line in mode 7500, 13100, 18200, 19800, 19900, 35300, 35400 or 38500 (`Token length exception`, `Separator unmatched`, `Signature unmatched`) | The `$user$realm$` layout was added to those modes after v8.0.0 and needs a build from master | [Mode matrix](cracking/hash-reference.md#mode-matrix) |
| hashcat rejects a line whose user field ends in `$` with `Token length exception` | A machine account name: the `$` is read as a field separator | [Correcting a line by hand](#correcting-a-line-by-hand) |
| hashcat rejects a DES line | The cipher hex is not a multiple of 16 chars, or user plus realm is over 128 bytes | [Parser rules](cracking/hashcat-internals.md#parser-rules) |
| Mode 39400 rejects a line that 7500 loads | 39400 does not take the single-field shape; a build of master older than 2026-11-25 also needs exactly 72 hex of encrypted timestamp | [Mode 39400](cracking/hashcat-internals.md#mode-39400-pre-auth-nt-hash-input) |
| hashcat aborts on a `$krb5pa$` line that carries an explicit salt | A build of master from between 2026-11-12 and 2026-11-23, and a salt longer than 513 chars | [Mode 19800](cracking/hashcat-internals.md#mode-19800-aes128) |
| An AS-REP line from a capture never cracks | It came from a smartcard or FAST-armored logon | [kw-extract](commands/kw-extract.md#kerberos-details) |
| `kw-roast` or `kw-asrep` returns nothing for a target | The KDC refused it; `-vv` shows the skipped targets | [Encryption type selection](commands/common-options.md#encryption-type-selection) |
| A `-k` LDAP bind fails with `Cannot find KDC for realm` | The system Kerberos library cannot find the KDC | [Kerberos setup](installation.md#kerberos-setup) |
| A `-k` LDAP bind is refused when only a DC IP is known | There is no hostname for the SPN | [Finding the domain controller](commands/common-options.md#finding-the-domain-controller) |
| An NTLM logon is in the capture but no hash is written | Its Type 2 challenge is not in the capture | [NTLM details](commands/kw-extract.md#ntlm-details) |
| A Kerberos message is missing from the output of a capture | A TCP segment was not captured | [kw-extract](commands/kw-extract.md#what-it-extracts) |
| An RC4 session runs slower than the speed table | The RC4 column of that table assumes `-O` | [Cracking Speed](cracking/speed.md#speed-by-etype-and-attack) |
| A RID gives no timeroast reply | MSA, dMSA and user accounts do not respond | [Which accounts respond](background/timeroasting.md#which-accounts-respond) |

## The user field is a cryptographic input

The hash line carries both cryptographic inputs and labels. Getting a label wrong breaks nothing. Getting a cryptographic input wrong means zero results with no error.

**RC4: only the ciphertext matters.** Everything else is a label.
**AES and DES: the ciphertext and the username and realm matter.** They are the salt. Get them wrong and hashcat silently produces nothing.

| Field | RC4 modes | AES modes | DES modes |
|-------|-----------|-----------|-----------|
| `etype` | Required (selects crypto) | Required | Required; in 38400 a label, because the key is the same for 1, 2 and 3 |
| `user` | Label | **Cryptographic**: PBKDF2 salt component (case-sensitive) | **Cryptographic**: string-to-key salt component (case-sensitive) |
| `realm` | Label | **Cryptographic**: PBKDF2 salt component (uppercased by hashcat) | **Cryptographic**: string-to-key salt component (uppercased by hashcat) |
| Explicit salt (JtR shapes) | Label (7500, 39400) | **Cryptographic**: PBKDF2 salt, used verbatim; user and realm are then labels | Not accepted |
| Checksum, ciphertext, stored key | Cryptographic: the checksum keys the RC4 decryption | Cryptographic: the checksum, or the stored key in the DB modes, is the verification target | Cryptographic: checksum plus edata2 are the DES-CBC ciphertext, and the stored key in 38400 is the verification target |
| `spn` | Label | Label | Label |

The RC4 modes are 7500, 13100, 18200, 35300, 35400 and 39400. The AES modes are 19600, 19700, 19800, 19900, 28800, 28900, 32100 and 32200. The DES modes are 38400, 38500, 38600, 39000, 39100, 39200 and 39300.

For the AES and DES modes:

- **Realm is uppercased at parse time.** hashcat calls `uppercase()` on the realm field when it builds the salt, so `contoso.com` and `Contoso.Com` both become `CONTOSO.COM`. The cracked line is printed back with the realm as you wrote it. The realm still has to be the KDC's realm.
- **Username is case-sensitive and left as-is.** If the account is `Administrator` and your hash says `administrator`, the derived key is different and cracking produces nothing, with no error.
- **Salt = `REALM` + `user`, concatenated.** No separator, no null byte: `CONTOSO.COMAdministrator`. AES feeds it to PBKDF2-HMAC-SHA1 with 4096 iterations, as `PBKDF2-HMAC-SHA1(password, REALM + user, 4096)` followed by the RFC 3962 key derivation; DES feeds it to the RFC 3961 string-to-key.

RC4 modes don't care about any of this. RC4 key derivation is `MD4(UTF-16LE(password))`: no salt, no username, no realm. The user, realm, salt and SPN fields are labels that exist so cracked results can be attributed back to accounts, and they can be empty or wrong and cracking still works.

The timeroast lines have no user field. In mode 31300 the MD5 digest and the salt (the NTP response header) are both inputs and the RID is not in the line at all; in `$sntp-ms-sha512$` the RID is an input too.

### Where each tool takes the name from

- **`kw-roast`** probes each target with an AS-REQ and reads the name from the salt in the KDC's answer. An SPN it could not resolve to an account ends up in the user field as it is. See [kw-roast](commands/kw-roast.md#behaviour).
- **`kw-asrep`** reads it from the salt in the AS-REP. See [kw-asrep](commands/kw-asrep.md#behaviour).
- **`kw-extract`** uses the salts the KDC sent within the same capture, and warns when it has none. A TGS-REP in ordinary Windows traffic names an SPN, not an account. See [kw-extract](commands/kw-extract.md#kerberos-details).

### Correcting a line by hand

Replace the user field with the name the key is salted with: the sAMAccountName, in its exact case, for a user account, and `host<fqdn>` in lower case for a computer account (`hostws01.corp.local` for `WS01$`). How those salts are built for each etype is under [Salt](background/encryption-types.md#salt) on the Encryption Types page.

An RC4 line needs no correction for cracking, with one exception: a user field that ends in `$`. hashcat splits the line on `$`, so `$krb5asrep$23$WS01$$CORP.LOCAL$...` does not load. `kw-asrep` and `kw-extract` write such a line for a machine account when the AS-REP is RC4, which carries no salt, and `kw-extract` also for a ticket whose account it has no salt for. Delete the trailing `$` of the name, or empty the field, and the line loads.

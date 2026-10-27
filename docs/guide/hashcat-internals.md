# Hashcat Internals

Field-by-field breakdown of how hashcat parses each Kerberos hash mode, sourced from the `module_*.c` files. Useful when a hash won't load, when you're building tooling that outputs these formats, or when you need to know which fields actually affect cracking vs which ones are just metadata.

Some modes accept multiple input formats. Format 1 is the canonical hashcat format in every case (what `module_hash_encode` outputs to the potfile). If you're generating hashes, use format 1.

## Quick reference

| Mode | Attack | Etype | Canonical format | Alt formats | User/realm required? |
|------|--------|-------|-----------------|-------------|---------------------|
| [13100](#mode-13100-rc4) | TGS-REP Roast (Kerberoast) | RC4 | `$krb5tgs$23$user$realm$chk$edata2` | [2](#mode-13100-rc4-format-2-no-account-info), [3](#mode-13100-rc4-format-3-colon-delimited-spn) | no |
| [19600](#mode-19600-aes128) | TGS-REP Roast (Kerberoast) | AES128-SHA1 | `$krb5tgs$17$user$realm$chk$edata2` | (+optional SPN) | **yes** |
| [19700](#mode-19700-aes256) | TGS-REP Roast (Kerberoast) | AES256-SHA1 | `$krb5tgs$18$user$realm$chk$edata2` | (+optional SPN) | **yes** |
| [39400](#mode-39400-aes128-sha2) | TGS-REP Roast (Kerberoast) | AES128-SHA2 | `$krb5tgs$19$user$realm$chk$edata2` | | **yes** |
| [39500](#mode-39500-aes256-sha2) | TGS-REP Roast (Kerberoast) | AES256-SHA2 | `$krb5tgs$20$user$realm$chk$edata2` | | **yes** |
| [38500](#mode-38500-des) | TGS-REP Roast (Kerberoast) | DES-CBC-MD5 | `$krb5tgs$3$user$realm$chk$edata2` | | **yes** |
| [39100](#mode-39100-des-crc) | TGS-REP Roast (Kerberoast) | DES-CBC-CRC | `$krb5tgs$1$user$realm$chk$edata2` | | **yes** |
| [18200](#mode-18200-rc4) | AS-REP Roast | RC4 | `$krb5asrep$23$user$realm$chk$edata2` | [2](#mode-18200-rc4-format-2-no-etype) | no |
| [32100](#mode-32100-aes128) | AS-REP Roast | AES128-SHA1 | `$krb5asrep$17$user$realm$chk$edata2` | [2](#mode-32100-aes128-format-2-checksum-after-edata2) | **yes** |
| [32200](#mode-32200-aes256) | AS-REP Roast | AES256-SHA1 | `$krb5asrep$18$user$realm$chk$edata2` | [2](#mode-32200-aes256-format-2-checksum-after-edata2) | **yes** |
| [39600](#mode-39600-asrep-sha2) | AS-REP Roast | AES128-SHA2 | `$krb5asrep$19$user$realm$chk$edata2` | | **yes** |
| [39700](#mode-39700-asrep-sha2) | AS-REP Roast | AES256-SHA2 | `$krb5asrep$20$user$realm$chk$edata2` | | **yes** |
| [38600](#mode-38600-des) | AS-REP Roast | DES-CBC-MD5 | `$krb5asrep$3$user$realm$chk$edata2` | (+joined `user@realm:`) | **yes** |
| [39200](#mode-39200-asrep-des-crc) | AS-REP Roast | DES-CBC-CRC | `$krb5asrep$1$user$realm$chk$edata2` | | **yes** |
| [7500](#mode-7500-rc4) | AS-REQ Pre-Auth | RC4 | `$krb5pa$23$user$realm$data` | | no |
| [19800](#mode-19800-aes128) | AS-REQ Pre-Auth | AES128-SHA1 | `$krb5pa$17$user$realm$data` | | **yes** |
| [19900](#mode-19900-aes256) | AS-REQ Pre-Auth | AES256-SHA1 | `$krb5pa$18$user$realm$data` | | **yes** |
| [39800](#mode-39800-pa-sha2) | AS-REQ Pre-Auth | AES128-SHA2 | `$krb5pa$19$user$realm$data` | | **yes** |
| [39900](#mode-39900-pa-sha2) | AS-REQ Pre-Auth | AES256-SHA2 | `$krb5pa$20$user$realm$data` | | **yes** |
| [39000](#mode-39000-pa-des) | AS-REQ Pre-Auth | DES-CBC-MD5 | `$krb5pa$3$user$realm$data` | | **yes** |
| [39300](#mode-39300-pa-des-crc) | AS-REQ Pre-Auth | DES-CBC-CRC | `$krb5pa$1$user$realm$data` | | **yes** |
| [28800](#mode-28800-aes128-db) | DB Key | AES128-SHA1 | `$krb5db$17$user$realm$key` | (+optional SPN) | **yes** |
| [28900](#mode-28900-aes256-db) | DB Key | AES256-SHA1 | `$krb5db$18$user$realm$key` | (+optional SPN) | **yes** |
| [39010](#mode-39010-db-sha2) | DB Key | AES128-SHA2 | `$krb5db$19$user$realm$key` | | **yes** |
| [39020](#mode-39020-db-sha2) | DB Key | AES256-SHA2 | `$krb5db$20$user$realm$key` | | **yes** |
| [38400](#mode-38400-des-db) | DB Key | DES 1/2/3 | `$krb5db$<1\|2\|3>$user$realm$key` | (+optional SPN) | **yes** |
| [35300](#mode-35300-rc4-nt) | TGS-REP (NT hash) | RC4 | same as 13100 | same as 13100 | no |
| [35400](#mode-35400-rc4-nt) | AS-REP (NT hash) | RC4 | same as 18200 | same as 18200 | no |
| [35900](#mode-35900-rc4-nt) | Pre-Auth (NT hash) | RC4 | same as 7500 | same as 7500 | no |
| [31300](#mode-31300-ms-sntp-68-byte-authenticator) | Timeroasting | MD5 | `$sntp-ms$digest$salt` | | no |

---

## Things that will silently break your crack

!!! warning "Case sensitivity and salt construction"
    For all AES modes (19600, 19700, 19800, 19900, 32100, 32200, 39400-39900):

    - **Realm is uppercased at parse time.** Hashcat calls `uppercase()` on the realm field, so `contoso.com` and `Contoso.Com` both become `CONTOSO.COM`. But the realm **must match the KDC's realm exactly** after uppercasing. A typo like `CONTOSO.COM` vs `CONTOSO.NET` will break everything.
    - **Username is case-sensitive and left as-is.** Hashcat does not touch the case of the user field. If the KDC issued the ticket for `Administrator` and your hash says `administrator`, the derived key will be different and cracking will produce zero results with no error message.
    - **AES-SHA1 salt = `REALM` + `user` concatenated.** No separator, no null byte. `CONTOSO.COMAdministrator`. Fed to PBKDF2-HMAC-SHA1 with 4096 iterations.
    - **AES-SHA2 salt = `etype_name` + `\x00` + `REALM` + `user`.** The etype name (e.g., `aes256-cts-hmac-sha384-192`) is prepended with a null byte separator. Fed to PBKDF2-HMAC-SHA256 (etype 19) or PBKDF2-HMAC-SHA384 (etype 20) with 4096 iterations, then KDF-HMAC-SHA2.
    - **Hex fields accept both cases.** `a-f` and `A-F` both work in checksum and edata2 fields.
    - **RC4 modes (7500, 13100, 18200) don't care about any of this.** The user/realm/salt/spn fields are display-only metadata. The NT hash has no salt, so those fields can be empty or wrong and cracking still works.

---

## TGS-REP Roast (Kerberoast)

### Mode 13100: RC4

**Module:** `module_13100.c`

```
$krb5tgs$23$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5tgs$` | | 9 chars | yes | |
| etype `23` | `$` | 2 digits | yes | |
| user | `$` | variable | yes (can be empty) | no |
| realm | `$` | variable | yes (can be empty) | no |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64-40958 hex | yes | yes |

Canonical format. User and realm are display metadata — hashcat stores them for the potfile but never uses them for cracking. Only checksum + edata2 matter. hashcat also accepts the Rubeus/Impacket `$krb5tgs$23$*user$realm$spn*$checksum$edata2` legacy wrapper (normalized to format 1 on output), plus format 2 (bare) and format 3 (colon-SPN) below. KerbWolf never emits the legacy wrapper.

#### Mode 13100: RC4 &mdash; format 2 (no account info)

```
$krb5tgs$23$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5tgs$` | | 9 chars | yes | |
| etype `23` | `$` | 2 digits | yes | |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64-40958 hex | yes | yes |

Detected when bytes after signature are `23$` but the next character is not `*`. Hashcat converts this to format 1 (with empty account info) on output.

#### Mode 13100: RC4 &mdash; format 3 (colon-delimited SPN)

```
$krb5tgs$spn:checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5tgs$` | | 9 chars | yes | |
| spn | `:` | 0-2047 chars | no | no |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64-40958 hex | yes | yes |

Detected when the bytes after signature are NOT `23`. No etype field, colon delimiter for SPN. Hashcat converts this to format 1 on output (canonical `$23$user$realm$` format).

---

### Mode 19600: AES128

**Module:** `module_19600.c`

```
$krb5tgs$17$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5tgs$17$` | | 12 chars | yes | |
| user | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt) |
| realm | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt, uppercased) |
| checksum | `$` | 24 hex (12 bytes) | yes | yes |
| edata2 | `$` | 64-40960 hex | yes | yes |

Also accepts `$krb5tgs$17$user$realm$*spn*$checksum$edata2` with an optional SPN wrapped in `*...*$` between realm and checksum. Hashcat detects this by looking for a `*` after position 13. The SPN is accepted but stripped from the canonical output.

User and realm are cryptographic inputs. Hashcat uppercases the realm at parse time, concatenates `REALM + user` (user case preserved), and feeds it to PBKDF2-HMAC-SHA1 (4096 iterations) as the salt.

### Mode 19700: AES256

**Module:** `module_19700.c`

```
$krb5tgs$18$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5tgs$18$` | | 12 chars | yes | |
| user | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt) |
| realm | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt, uppercased) |
| checksum | `$` | 24 hex (12 bytes) | yes | yes |
| edata2 | `$` | 64-40960 hex | yes | yes |

Same parser as 19600. Accepts the optional `*spn*$` field. Only the signature (`18` vs `17`) and key length (32 bytes vs 16) differ.

### Mode 39400: AES128-SHA2 TGS-REP {: #mode-39400-aes128-sha2 }

**Module:** `module_39400.c`

```
$krb5tgs$19$user$realm$checksum$edata2
```

Same field layout as 19600/19700. User and realm feed PBKDF2-HMAC-SHA256 (4096 iterations) with the etype name prefix salt (`aes128-cts-hmac-sha256-128\x00REALM + user`), followed by a KDF-HMAC-SHA2 second pass. Checksum is 32 hex (16 bytes, HMAC-SHA256-128).

### Mode 39500: AES256-SHA2 TGS-REP {: #mode-39500-aes256-sha2 }

**Module:** `module_39500.c`

```
$krb5tgs$20$user$realm$checksum$edata2
```

Same as 39400 but with PBKDF2-HMAC-SHA384 and a 48-hex checksum (24 bytes, HMAC-SHA384-192). Key output is 32 bytes.

---

## AS-REP Roast

### Mode 18200: RC4

**Module:** `module_18200.c`

```
$krb5asrep$23$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5asrep$` | | 11 chars | yes | |
| etype `23` | `$` | 2 digits | yes | |
| user | `$` | variable | no | no |
| realm | `$` | variable | no | no |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64-40958 hex | yes | yes |

Canonical format. hashcat also accepts the legacy `$krb5asrep$23$user@realm:checksum$edata2` (Impacket format) on input. KerbWolf emits the canonical `$`-delimited format.

#### Mode 18200: RC4 &mdash; format 2 (no etype)

```
$krb5asrep$user@realm:checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5asrep$` | | 11 chars | yes | |
| user principal | `:` | variable | no | no |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64-40958 hex | yes | yes |

Detected when bytes after signature are NOT `23`. Same fields minus the etype. Hashcat converts this to format 1 (with `23$`) on output.

For both 18200 formats: user principal is metadata, only checksum + edata2 are used for cracking.

---

### Mode 32100: AES128

**Module:** `module_32100.c`

```
$krb5asrep$17$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5asrep$17$` | | 14 chars | yes | |
| user | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt) |
| realm | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt, uppercased) |
| checksum | `$` | 24 hex (12 bytes) | yes | yes |
| edata2 | `$` | 64-40960 hex | yes | yes |

Canonical format. Detected when the character at position `line_len - 25` is NOT `$`. Hashcat uppercases the realm and builds the salt as `REALM + user`.

#### Mode 32100: AES128 &mdash; format 2 (checksum after edata2)

```
$krb5asrep$17$salt$edata2$checksum
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5asrep$17$` | | 14 chars | yes | |
| salt | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt, used directly) |
| edata2 | `$` | 64-40960 hex | yes | yes |
| checksum | `$` | 24 hex (12 bytes) | yes | yes |

Detected when the character at position `line_len - 25` IS `$` (checksum is always 24 hex, so `$` at that offset means it's the last field). Field order is flipped: edata2 before checksum. The salt field is used directly as the PBKDF2 input (should already be `REALMuser`). Hashcat converts this to format 1 on output.

### Mode 32200: AES256

**Module:** `module_32200.c`

```
$krb5asrep$18$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5asrep$18$` | | 14 chars | yes | |
| user | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt) |
| realm | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt, uppercased) |
| checksum | `$` | 24 hex (12 bytes) | yes | yes |
| edata2 | `$` | 64-40960 hex | yes | yes |

Canonical format. Same parser as 32100.

#### Mode 32200: AES256 &mdash; format 2 (checksum after edata2)

```
$krb5asrep$18$salt$edata2$checksum
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5asrep$18$` | | 14 chars | yes | |
| salt | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt, used directly) |
| edata2 | `$` | 64-40960 hex | yes | yes |
| checksum | `$` | 24 hex (12 bytes) | yes | yes |

Same as 32100 format 2. Converted to format 1 on output.

### Mode 39600: AES128-SHA2 AS-REP {: #mode-39600-asrep-sha2 }

**Module:** `module_39600.c`

```
$krb5asrep$19$user$realm$checksum$edata2
```

Same field layout as 32100/32200 but with SHA2 key derivation (PBKDF2-HMAC-SHA256 + KDF, etype name prefix salt). Checksum is 32 hex (16 bytes).

### Mode 39700: AES256-SHA2 AS-REP {: #mode-39700-asrep-sha2 }

**Module:** `module_39700.c`

```
$krb5asrep$20$user$realm$checksum$edata2
```

Same as 39600 but with PBKDF2-HMAC-SHA384 and a 48-hex checksum (24 bytes). Key output is 32 bytes.

### Mode 39200: DES-CBC-CRC AS-REP {: #mode-39200-asrep-des-crc }

**Module:** `module_39200.c`

```
$krb5asrep$1$user$realm$checksum$edata2
```

Same as mode 38600 (DES-CBC-MD5 AS-REP) but for etype 1 (DES-CBC-CRC). Signature is `$krb5asrep$1$`.

---

## AS-REQ Pre-Auth

### Mode 7500: RC4

**Module:** `module_07500.c`

```
$krb5pa$23$user$realm$data
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5pa$23$` | | 11 chars | yes | |
| user | `$` | 0-63 chars | no | no |
| realm | `$` | 0-63 chars | no | no |
| data (enc_timestamp + checksum) | `$` | 104 hex | yes | yes |

Single format. User and realm can be empty strings. Hashcat stores the metadata fields for display but ignores them during cracking. The data field is one concatenated blob: 72 hex chars of encrypted timestamp followed by 32 hex chars of HMAC-MD5 checksum. Only the data field matters for cracking. hashcat also accepts `$krb5pa$23$user$realm$salt$data` with an extra salt field (John format); KerbWolf does not emit the salt field.

---

### Mode 19800: AES128

**Module:** `module_19800.c`

```
$krb5pa$17$user$realm$data
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5pa$17$` | | 11 chars | yes | |
| user | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt) |
| realm | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt, uppercased) |
| data (enc_timestamp + checksum) | `$` | 104-112 hex | yes | yes |

Single format. The data field is one blob that hashcat splits internally: the last 24 hex chars (12 bytes) are the HMAC-SHA1 checksum, everything before that is the encrypted timestamp.

112-char data = 88 hex enc_timestamp + 24 hex checksum.
104-char data = 80 hex enc_timestamp + 24 hex checksum.

Same salt construction as all AES modes: uppercase realm + user → PBKDF2 4096 iterations.

### Mode 19900: AES256

**Module:** `module_19900.c`

```
$krb5pa$18$user$realm$data
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5pa$18$` | | 11 chars | yes | |
| user | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt) |
| realm | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt, uppercased) |
| data (enc_timestamp + checksum) | `$` | 104-112 hex | yes | yes |

Same parser as 19800. Signature is `$krb5pa$18$`, key output is 32 bytes instead of 16.

### Mode 39800: AES128-SHA2 Pre-Auth {: #mode-39800-pa-sha2 }

**Module:** `module_39800.c`

```
$krb5pa$19$user$realm$data
```

Same field layout as 19800/19900. Key derivation uses PBKDF2-HMAC-SHA256 with the etype name prefix salt, followed by KDF-HMAC-SHA2. The module uses `salt_iter = 32768 - 1` (RFC 8009 default); see the [encryption types warning](encryption-types.md#aes128-sha2-and-aes256-sha2-etypes-19-and-20) about the Windows 4096-iteration mismatch. The `data` field contains the encrypted timestamp followed by a 32-hex HMAC-SHA256-128 checksum.

### Mode 39900: AES256-SHA2 Pre-Auth {: #mode-39900-pa-sha2 }

**Module:** `module_39900.c`

```
$krb5pa$20$user$realm$data
```

Same as 39800 but with PBKDF2-HMAC-SHA384 and a 48-hex HMAC-SHA384-192 checksum. Key output is 32 bytes.

### Mode 39000: DES-CBC-MD5 Pre-Auth {: #mode-39000-pa-des }

**Module:** `module_39000.c`

```
$krb5pa$3$user$realm$data
```

DES string-to-key from `REALM + user`, then DES-CBC decrypt the encrypted timestamp. Signature is `$krb5pa$3$`.

### Mode 39300: DES-CBC-CRC Pre-Auth {: #mode-39300-pa-des-crc }

**Module:** `module_39300.c`

```
$krb5pa$1$user$realm$data
```

Same as 39000 but for etype 1 (DES-CBC-CRC). Signature is `$krb5pa$1$`.

---

## Timeroasting (MS-SNTP)

### Mode 31300: MS-SNTP (68-byte Authenticator)

**Module:** `module_31300.c`

```
$sntp-ms$<32hex_digest>$<96hex_salt>
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$sntp-ms$` | | 9 chars | yes | |
| MD5 digest | `$` | 32 hex | yes | yes |
| salt (NTP response header) | `$` | 96 hex (48 bytes) | yes | yes |

The hash is computed as `MD5(NTOWFv1 || salt)` where NTOWFv1 is the NT hash (MD4 of the UTF-16LE password) and salt is the 48-byte NTP server response header.

The RID identifies the computer or trust account but is not part of the hash string and is not used in the MD5 computation. KerbWolf preserves it in the output line prefix (e.g., `1103:$sntp-ms$...`) for account mapping.

### Proposed: MS-SNTP SHA512 (120-byte ExtendedAuthenticator)

No hashcat module exists for this format yet. The proposed format:

```
$sntp-ms-sha512$<RID>$<128hex_digest>$<96hex_salt>
```

| Field | Length | Used for cracking |
|-------|--------|-------------------|
| RID | 1-10 digits | **yes** (KDF context input) |
| HMAC-SHA512 digest | 128 hex (64 bytes) | yes |
| salt (NTP response header) | 96 hex (48 bytes) | yes |

Unlike mode 31300 where the RID is metadata, the SHA512 format **requires** the RID for cracking. It feeds the SP800-108 KDF as the Context parameter:

```
derived_key = KDF(SP800-108, PRF=HMAC-SHA512, Key=NTOWFv1,
    data = counter(4,BE) || "sntp-ms\0" || 0x00 || RID(4,LE) || 512(4,BE))
checksum = HMAC-SHA512(derived_key, salt)
```

---

## DES Kerberoast / AS-REP Roast

### Mode 38500: DES TGS-REP {: #mode-38500-des }

**Module:** `module_38500.c`

```
$krb5tgs$3$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5tgs$3$` | | 11 chars | yes | |
| user | `$` | 1-127 chars | **yes** | **yes** (DES string-to-key salt) |
| realm | `$` | 1-127 chars | **yes** | **yes** (DES string-to-key salt, uppercased) |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64+ hex | yes | yes |

Unlike RC4 mode 13100 where user/realm are pure metadata, DES requires them. The salt for DES string-to-key is `REALM + user`, same as AES. The "checksum" field is the first 2 DES blocks of ciphertext, not a MAC — the real integrity check (MD5) is embedded in the plaintext after decryption.

Verification: CBC-decrypt the second block of edata2 (bytes 24-31 of full ciphertext, XOR'd with the previous ciphertext block), check for ASN.1 tag `0x63` (EncTicketPart). On match, decrypt full ciphertext, zero the embedded MD5 at plaintext bytes 8-24, recompute MD5, compare.

### Mode 39100: DES-CBC-CRC TGS-REP {: #mode-39100-des-crc }

**Module:** `module_39100.c`

```
$krb5tgs$1$user$realm$checksum$edata2
```

Same as 38500 but for etype 1 (DES-CBC-CRC). Integrity check uses CRC32 instead of MD5. Signature is `$krb5tgs$1$`.

### Mode 38600: DES AS-REP {: #mode-38600-des }

**Module:** `module_38600.c`

```
$krb5asrep$3$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5asrep$3$` | | 13 chars | yes | |
| user | `$` | 1-127 chars | **yes** | **yes** (DES string-to-key salt) |
| realm | `$` | 1-127 chars | **yes** | **yes** (DES string-to-key salt, uppercased) |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64+ hex | yes | yes |

Also accepts joined format: `$krb5asrep$3$user@realm:checksum$edata2`. Same kernel as 38500 but checks for ASN.1 tags `0x79`/`0x7a` (application 25/26 = EncASRepPart/EncTGSRepPart) instead of `0x63`.

---

## DB Key (extracted from NTDS.dit)

### Mode 28800: AES128 DB Key {: #mode-28800-aes128-db }

**Module:** `module_28800.c`

```
$krb5db$17$user$realm$<32hex_key>
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5db$17$` | | 11 chars | yes | |
| user | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt) |
| realm | `$` | 1-512 chars | **yes** | **yes** (PBKDF2 salt, uppercased) |
| stored key | `$` | 32 hex (16 bytes) | yes | yes |

No ciphertext — derives the AES-128 key from the candidate password via PBKDF2-HMAC-SHA1 (4096 iterations) and compares directly to the stored key. Also accepts an optional `*spn*$` block before the key (stripped on output).

### Mode 28900: AES256 DB Key {: #mode-28900-aes256-db }

**Module:** `module_28900.c`

Same as 28800 with `$krb5db$18$` signature and 64 hex (32 bytes) for the stored key.

### Mode 39010: AES128-SHA2 DB Key {: #mode-39010-db-sha2 }

**Module:** `module_39010.c`

```
$krb5db$19$user$realm$key
```

Same field layout as 28800 but with SHA2 key derivation (PBKDF2-HMAC-SHA256 + KDF, etype name prefix salt). Key field is 32 hex (16 bytes).

### Mode 39020: AES256-SHA2 DB Key {: #mode-39020-db-sha2 }

**Module:** `module_39020.c`

```
$krb5db$20$user$realm$key
```

Same as 39010 but with PBKDF2-HMAC-SHA384 and 64-hex key output (32 bytes).

### Mode 38400: DES DB Key {: #mode-38400-des-db }

**Module:** `module_38400.c`

```
$krb5db$<1|2|3>$user$realm$<16hex_key>
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5db$<1\|2\|3>$` | | 10 chars | yes | |
| user | `$` | 1-127 chars | **yes** | **yes** (DES string-to-key salt) |
| realm | `$` | 1-127 chars | **yes** | **yes** (DES string-to-key salt) |
| stored key | `$` | 16 hex (8 bytes) | yes | yes |

Accepts etypes 1, 2, and 3. The etype digit is stored for round-trip encoding but has no effect on cracking — DES string-to-key produces the same 8-byte key for all three. Also accepts an optional `*spn*$` block before the key.

---

## NT Hash Input (pass-the-hash Kerberoasting)

### Mode 35300: RC4 TGS-REP, NT hash input {: #mode-35300-rc4-nt }

**Module:** `module_35300.c`

Identical hash format to mode 13100. The difference is the input: the wordlist contains 32-hex NT hashes instead of passwords. Hashcat skips the MD4 key derivation and uses the NT hash directly as the RC4 key. Use this for pass-the-hash Kerberoasting when you have NT hashes from a dump but not the plaintext passwords.

### Mode 35400: RC4 AS-REP, NT hash input {: #mode-35400-rc4-nt }

**Module:** `module_35400.c`

Same relationship to mode 18200. Identical hash format, NT hash as input.

### Mode 35900: RC4 Pre-Auth, NT hash input {: #mode-35900-rc4-nt }

**Module:** `module_35900.c`

Same relationship to mode 7500. Identical hash format, NT hash as input.

---

## What hashcat actually needs to crack each hash

The hash line carries both cryptographic inputs (required) and display metadata (ignored during cracking). Getting a metadata field wrong doesn't break anything. Getting a cryptographic input wrong means zero results with no error.

### RC4 modes (7500, 13100, 18200, 35300, 35400, 35900)

| Field | Role | Wrong value breaks cracking? |
|-------|------|------------------------------|
| checksum | Cryptographic — HMAC-MD5 verification target | Yes |
| edata2 | Cryptographic — encrypted ciphertext | Yes |
| user | Display metadata | No |
| realm | Display metadata | No |
| spn | Display metadata | No |
| salt (7500 only) | Display metadata | No |

RC4 key derivation is `MD4(UTF-16LE(password))` — no salt, no username, no realm. The metadata fields exist so cracked results can be attributed back to accounts. You can leave them empty or wrong and cracking still works.

### AES modes (19600, 19700, 19800, 19900, 28800, 28900, 32100, 32200, 39010, 39020, 39400-39900)

| Field | Role | Wrong value breaks cracking? |
|-------|------|------------------------------|
| checksum / stored key | Cryptographic — verification target | Yes |
| edata2 / enc_timestamp | Cryptographic — encrypted ciphertext | Yes |
| user | **Cryptographic** — PBKDF2 salt component (case-sensitive) | **Yes** |
| realm | **Cryptographic** — PBKDF2 salt component (uppercased by hashcat) | **Yes** |
| spn | Display metadata | No |

AES-SHA1 key derivation is `PBKDF2-HMAC-SHA1(password, REALM + user, 4096)`. AES-SHA2 adds an etype name prefix to the salt and uses PBKDF2-HMAC-SHA256/384 + KDF-HMAC-SHA2. In both cases, the salt includes the uppercase realm and case-preserved username. Wrong username case = wrong salt = wrong key = silent failure.

### DES modes (38400, 38500, 38600, 39000, 39100, 39200, 39300)

| Field | Role | Wrong value breaks cracking? |
|-------|------|------------------------------|
| checksum / stored key | Cryptographic — first 2 DES blocks (38500/38600) or stored key (38400) | Yes |
| edata2 | Cryptographic — remaining ciphertext | Yes (38500/38600) |
| user | **Cryptographic** — DES string-to-key salt component | **Yes** |
| realm | **Cryptographic** — DES string-to-key salt component | **Yes** |
| spn | Display metadata | No |
| etype digit (38400) | Display metadata — string-to-key is identical for 1/2/3 | No |

DES string-to-key uses `REALM + user` as salt, same as AES. The etype digit in mode 38400 (`$krb5db$1$` vs `$krb5db$3$`) does not affect cracking.

### Timeroast (31300)

| Field | Role | Wrong value breaks cracking? |
|-------|------|------------------------------|
| MD5 digest | Cryptographic — verification target | Yes |
| salt | Cryptographic — NTP response header fed to MD5 | Yes |
| RID | Display metadata (68-byte format) | No |

### Summary rule

**RC4: only the ciphertext matters.** Everything else is a label.
**AES and DES: the ciphertext AND the username+realm matter.** They're cryptographic salt inputs. Get them wrong and hashcat silently produces nothing.

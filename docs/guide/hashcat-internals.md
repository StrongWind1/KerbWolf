# Hashcat Internals

Field-by-field breakdown of how hashcat parses each Kerberos hash mode, sourced from the `module_*.c` files. Useful when a hash won't load, when you're building tooling that outputs these formats, or when you need to know which fields actually affect cracking vs which ones are just metadata.

Some modes accept multiple input formats. Format 1 is the canonical hashcat format in every case (what `module_hash_encode` outputs to the potfile). If you're generating hashes, use format 1.

## Quick reference

| Mode | Attack | Etype | Canonical format | Alt formats | User/realm required? |
|------|--------|-------|-----------------|-------------|---------------------|
| [13100](#mode-13100-rc4) | TGS-REP Roast (Kerberoast) | RC4 | `$krb5tgs$23$*user$realm$spn*$chk$edata2` | [2](#mode-13100-rc4-format-2-no-account-info), [3](#mode-13100-rc4-format-3-colon-delimited-spn) | no |
| [19600](#mode-19600-aes128) | TGS-REP Roast (Kerberoast) | AES128 | `$krb5tgs$17$user$realm$chk$edata2` | (+optional SPN) | **yes** |
| [19700](#mode-19700-aes256) | TGS-REP Roast (Kerberoast) | AES256 | `$krb5tgs$18$user$realm$chk$edata2` | (+optional SPN) | **yes** |
| [18200](#mode-18200-rc4) | AS-REP Roast | RC4 | `$krb5asrep$23$user@realm:chk$edata2` | [2](#mode-18200-rc4-format-2-no-etype) | no |
| [32100](#mode-32100-aes128) | AS-REP Roast | AES128 | `$krb5asrep$17$user$realm$chk$edata2` | [2](#mode-32100-aes128-format-2-checksum-after-edata2) | **yes** |
| [32200](#mode-32200-aes256) | AS-REP Roast | AES256 | `$krb5asrep$18$user$realm$chk$edata2` | [2](#mode-32200-aes256-format-2-checksum-after-edata2) | **yes** |
| [7500](#mode-7500-rc4) | AS-REQ Pre-Auth | RC4 | `$krb5pa$23$user$realm$salt$edata2checksum` | | no |
| [19800](#mode-19800-aes128) | AS-REQ Pre-Auth | AES128 | `$krb5pa$17$user$realm$data` | | **yes** |
| [19900](#mode-19900-aes256) | AS-REQ Pre-Auth | AES256 | `$krb5pa$18$user$realm$data` | | **yes** |
| [31300](#mode-31300-ms-sntp-68-byte-authenticator) | Timeroasting | MD5 | `$sntp-ms$RID$digest$salt` | | no |

---

## Things that will silently break your crack

!!! warning "Case sensitivity and salt construction"
    For all 6 AES modes (19600, 19700, 19800, 19900, 32100, 32200):

    - **Realm is uppercased at parse time.** Hashcat calls `uppercase()` on the realm field, so `contoso.com` and `Contoso.Com` both become `CONTOSO.COM`. But the realm **must match the KDC's realm exactly** after uppercasing. A typo like `CONTOSO.COM` vs `CONTOSO.NET` will break everything.
    - **Username is case-sensitive and left as-is.** Hashcat does not touch the case of the user field. If the KDC issued the ticket for `Administrator` and your hash says `administrator`, the derived key will be different and cracking will produce zero results with no error message.
    - **Salt = `REALM` + `user` concatenated.** No separator, no null byte. `CONTOSO.COMAdministrator`. Fed to PBKDF2-HMAC-SHA1 with 4096 iterations.
    - **Hex fields accept both cases.** `a-f` and `A-F` both work in checksum and edata2 fields.
    - **RC4 modes (7500, 13100, 18200) don't care about any of this.** The user/realm/salt/spn fields are display-only metadata. The NT hash has no salt, so those fields can be empty or wrong and cracking still works.

---

## TGS-REP Roast (Kerberoast)

### Mode 13100: RC4

**Module:** `module_13100.c`

```
$krb5tgs$23$*user$realm$spn*$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5tgs$` | | 9 chars | yes | |
| etype `23` | `$` | 2 digits | yes | |
| account info `*user$realm$spn*` | `$` | variable | yes (can be `**`) | no |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64-40960 hex | yes | yes |

Canonical format. Detected when bytes after signature are `23$*`. Account info between the asterisks is opaque to hashcat: it stores whatever is there and writes it back to the potfile, but never parses user/realm/spn from it. Cracking uses only checksum + edata2.

#### Mode 13100: RC4 &mdash; format 2 (no account info)

```
$krb5tgs$23$checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5tgs$` | | 9 chars | yes | |
| etype `23` | `$` | 2 digits | yes | |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64-40960 hex | yes | yes |

Detected when bytes after signature are `23$` but the next character is not `*`. Hashcat converts this to format 1 (with empty account info) on output.

#### Mode 13100: RC4 &mdash; format 3 (colon-delimited SPN)

```
$krb5tgs$spn:checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5tgs$` | | 9 chars | yes | |
| spn | `:` | 0-2048 chars | no | no |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64-40960 hex | yes | yes |

Detected when the bytes after signature are NOT `23`. No etype field, colon delimiter for SPN. Hashcat preserves this format on output (does not convert to format 1).

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

---

## AS-REP Roast

### Mode 18200: RC4

**Module:** `module_18200.c`

```
$krb5asrep$23$user@realm:checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5asrep$` | | 11 chars | yes | |
| etype `23` | `$` | 2 digits | yes | |
| user principal | `:` | variable | no | no |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64-40960 hex | yes | yes |

Canonical format. Detected when bytes after signature are `23$`. Note the `:` between user principal and checksum, not `$`.

#### Mode 18200: RC4 &mdash; format 2 (no etype)

```
$krb5asrep$user@realm:checksum$edata2
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5asrep$` | | 11 chars | yes | |
| user principal | `:` | variable | no | no |
| checksum | `$` | 32 hex (16 bytes) | yes | yes |
| edata2 | `$` | 64-40960 hex | yes | yes |

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

---

## AS-REQ Pre-Auth

### Mode 7500: RC4

**Module:** `module_07500.c`

```
$krb5pa$23$user$realm$salt$edata2checksum
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$krb5pa$23$` | | 11 chars | yes | |
| user | `$` | 0-64 chars | no | no |
| realm | `$` | 0-64 chars | no | no |
| salt | `$` | 0-128 chars | no | no |
| data (enc_timestamp + checksum) | `$` | 104 hex | yes | yes |

Single format. User, realm, and salt can all be empty strings — KerbWolf emits an empty salt, producing `$$` before the data. Hashcat stores the metadata fields for display but ignores them during cracking. The data field is one concatenated blob: 72 hex chars of encrypted timestamp followed by 32 hex chars of HMAC-MD5 checksum. Only the data field matters for cracking.

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

---

## Timeroasting (MS-SNTP)

### Mode 31300: MS-SNTP (68-byte Authenticator)

**Module:** `module_31300.c`

```
$sntp-ms$<RID>$<32hex_digest>$<96hex_salt>
```

| Field | Delimiter | Length | Required | Used for cracking |
|-------|-----------|--------|----------|-------------------|
| signature `$sntp-ms$` | | 9 chars | yes | |
| RID | `$` | 1-10 digits | yes | **no** (metadata only) |
| MD5 digest | `$` | 32 hex | yes | yes |
| salt (NTP response header) | `$` | 96 hex (48 bytes) | yes | yes |

The hash is computed as `MD5(NTOWFv1 || salt)` where NTOWFv1 is the NT hash (MD4 of the UTF-16LE password) and salt is the 48-byte NTP server response header.

The RID identifies the computer or trust account. It is not used in the MD5 computation but is preserved in the hash string so cracked passwords can be mapped back to accounts. Hashcat stores it in `salt_buf_pc` and emits it in the potfile output.

!!! note "Format change"
    The original module_31300.c used `$sntp-ms$<hash>$<salt>` (3 tokens, no RID). KerbWolf's updated module adds the RID as a 4th token between the signature and the digest.

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

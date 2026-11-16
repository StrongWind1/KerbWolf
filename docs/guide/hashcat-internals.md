# Hashcat Internals

Field-by-field breakdown of how hashcat parses each Kerberos hash mode, read from the `module_*.c` files of hashcat master (commit `d62291d29`, 2026-11-15). Useful when a hash won't load, when you're building tooling that outputs these formats, or when you need to know which fields affect cracking and which are only labels.

hashcat has 21 Kerberos modes: 7500, 13100, 18200, 19600, 19700, 19800, 19900, 28800, 28900, 32100, 32200, 35300, 35400, 38400, 38500, 38600, 39000, 39100, 39200, 39300 and 39400. There is no mode for etypes 19 and 20 (AES-SHA2). Modes 39000 through 39400 were added after the v8.0.0 release.

Most modes accept more than one line shape. hashcat prints a cracked hash back in the shape it was loaded in, so nothing is converted to a single layout. The one exception is the optional `*spn*` field of modes 19600, 19700, 28800, 28900 and 38400, which is accepted and then dropped. The "canonical" shape below is the `$user$realm$` layout that every mode accepts. KerbWolf writes it for the TGS-REP, AS-REP and Pre-Auth modes, and hashcat's `tools/krb5db2hashcat.py` writes it for the DB key modes.

## Quick reference

| Mode | Attack | Etype | Canonical line | Other accepted shapes | User/realm are salt? |
|------|--------|-------|----------------|-----------------------|----------------------|
| [13100](#mode-13100-rc4) | TGS-REP | 23 | `$krb5tgs$23$user$realm$checksum$edata2` | `*user$realm$spn*` block, bare, `spn:` | no |
| [19600](#mode-19600-aes128) | TGS-REP | 17 | `$krb5tgs$17$user$realm$checksum$edata2` | optional `*spn*` | **yes** |
| [19700](#mode-19700-aes256) | TGS-REP | 18 | `$krb5tgs$18$user$realm$checksum$edata2` | optional `*spn*` | **yes** |
| [38500](#mode-38500-des-cbc-md5) | TGS-REP | 3 | `$krb5tgs$3$user$realm$checksum$edata2` | `*user$realm$spn*` block | **yes** |
| [39100](#mode-39100-des-cbc-crc) | TGS-REP | 1 | `$krb5tgs$1$user$realm$checksum$edata2` | `*user$realm$spn*` block | **yes** |
| [18200](#mode-18200-rc4) | AS-REP | 23 | `$krb5asrep$23$user$realm$checksum$edata2` | `user@realm:` with or without `23$` | no |
| [32100](#mode-32100-aes128) | AS-REP | 17 | `$krb5asrep$17$user$realm$checksum$edata2` | `salt$edata2$checksum` | **yes** |
| [32200](#mode-32200-aes256) | AS-REP | 18 | `$krb5asrep$18$user$realm$checksum$edata2` | `salt$edata2$checksum` | **yes** |
| [38600](#mode-38600-des-cbc-md5) | AS-REP | 3 | `$krb5asrep$3$user$realm$checksum$edata2` | `user@realm:` | **yes** |
| [39200](#mode-39200-des-cbc-crc) | AS-REP | 1 | `$krb5asrep$1$user$realm$checksum$edata2` | `user@realm:` | **yes** |
| [7500](#mode-7500-rc4) | AS-REQ Pre-Auth | 23 | `$krb5pa$23$user$realm$checksum$encrypted` | salt field, single field | no |
| [19800](#mode-19800-aes128) | AS-REQ Pre-Auth | 17 | `$krb5pa$17$user$realm$checksum$encrypted` | single field, empty salt, explicit salt | **yes** |
| [19900](#mode-19900-aes256) | AS-REQ Pre-Auth | 18 | `$krb5pa$18$user$realm$checksum$encrypted` | single field, empty salt, explicit salt | **yes** |
| [39000](#mode-39000-des-cbc-md5) | AS-REQ Pre-Auth | 3 | `$krb5pa$3$user$realm$cipher` | split after 32 hex | **yes** |
| [39300](#mode-39300-des-cbc-crc) | AS-REQ Pre-Auth | 1 | `$krb5pa$1$user$realm$cipher` | split after 32 hex | **yes** |
| [28800](#mode-28800-aes128-db-key) | DB Key | 17 | `$krb5db$17$user$realm$key` | optional `*spn*` | **yes** |
| [28900](#mode-28900-aes256-db-key) | DB Key | 18 | `$krb5db$18$user$realm$key` | optional `*spn*` | **yes** |
| [38400](#mode-38400-des-db-key) | DB Key | 1, 2, 3 | `$krb5db$<1\|2\|3>$user$realm$key` | optional `*spn*` | **yes** |
| [35300](#mode-35300-tgs-rep-nt-hash-input) | TGS-REP (NT) | 23 | same as 13100 | same as 13100 | no |
| [35400](#mode-35400-as-rep-nt-hash-input) | AS-REP (NT) | 23 | same as 18200 | same as 18200 | no |
| [39400](#mode-39400-pre-auth-nt-hash-input) | AS-REQ Pre-Auth (NT) | 23 | same as 7500 | salt field only | no |
| [31300](#mode-31300-ms-sntp-68-byte-authenticator) | Timeroasting | MD5 | `$sntp-ms$digest$salt` | | no |

---

## Things that will silently break your crack

!!! warning "Case sensitivity and salt construction"
    For the AES modes (19600, 19700, 19800, 19900, 28800, 28900, 32100, 32200) and the DES modes (38400, 38500, 38600, 39000, 39100, 39200, 39300):

    - **Realm is uppercased at parse time.** hashcat calls `uppercase()` on the realm field when it builds the salt, so `contoso.com` and `Contoso.Com` both become `CONTOSO.COM`. The cracked line is printed back with the realm as you wrote it. The realm still has to be the KDC's realm.
    - **Username is case-sensitive and left as-is.** If the account is `Administrator` and your hash says `administrator`, the derived key is different and cracking produces nothing, with no error.
    - **Salt = `REALM` + `user`, concatenated.** No separator, no null byte: `CONTOSO.COMAdministrator`. AES feeds it to PBKDF2-HMAC-SHA1 with 4096 iterations; DES feeds it to the RFC 3961 string-to-key.
    - **An explicit salt field is used verbatim.** The JtR shapes of 32100/32200 (`salt$edata2$checksum`) and 19800/19900 (`user$realm$salt$data`) take the salt exactly as written, with no uppercasing.
    - **DES modes cap the salt and the password.** User plus realm may be at most 128 bytes together, and candidate passwords at most 64 bytes.
    - **DES ciphertext must be whole blocks.** The hex of the cipher has to be a multiple of 16 chars (8 bytes), or the line is rejected.
    - **Hex fields accept both cases.** `a-f` and `A-F` both load; hashcat prints lowercase.
    - **RC4 modes (7500, 13100, 18200, 35300, 35400, 39400) don't care about any of this.** The user, realm, salt and SPN fields are labels. The NT hash has no salt, so those fields can be empty or wrong and cracking still works.

---

## TGS-REP Roast (Kerberoast)

### Mode 13100: RC4

**Module:** `module_13100.c`

```
$krb5tgs$23$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5tgs$` | | 9 chars | |
| etype `23` | `$` | 2 digits | |
| user | `$` | 0-511 chars | no |
| realm | `$` | 0-511 chars | no |
| checksum | `$` | 32 hex (16 bytes) | yes |
| edata2 | `$` | 64-40958 hex | yes |

User and realm are labels and may be empty. Only checksum and edata2 matter. Three other shapes load:

| Shape | Detected when |
|-------|---------------|
| `$krb5tgs$23$*user$realm$spn*$checksum$edata2` (Rubeus, Impacket) | `23$` is followed by `*` |
| `$krb5tgs$23$checksum$edata2` (bare) | `23$` is followed by fewer than three more `$` |
| `$krb5tgs$spn:checksum$edata2` (JtR) | the signature is not followed by `23$` |

The canonical shape is chosen when `23$` is followed by at least three more `$`. The `*...*` block may be up to 2046 chars (2047 counting the `$` that follows it), the JtR SPN 0-2047 chars.

---

### Mode 19600: AES128

**Module:** `module_19600.c`

```
$krb5tgs$17$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5tgs$17$` | | 12 chars | |
| user | `$` | 1-511 chars | **yes** (PBKDF2 salt) |
| realm | `$` | 1-511 chars | **yes** (PBKDF2 salt, uppercased) |
| checksum | `$` | 24 hex (12 bytes) | yes |
| edata2 | `$` | 64-40960 hex | yes |

Also accepts `$krb5tgs$17$user$realm$*spn*$checksum$edata2`, with an SPN wrapped in `*...*$` between realm and checksum. The SPN is dropped: the line is printed back without it.

hashcat uppercases the realm, concatenates `REALM + user` (user case preserved), and feeds it to PBKDF2-HMAC-SHA1 (4096 iterations) as the salt.

### Mode 19700: AES256

**Module:** `module_19700.c`

```
$krb5tgs$18$user$realm$checksum$edata2
```

Same parser and limits as 19600, including the optional `*spn*$` field. The signature is `$krb5tgs$18$` and the key is 32 bytes instead of 16.

### Mode 38500: DES-CBC-MD5

**Module:** `module_38500.c`

```
$krb5tgs$3$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5tgs$3$` | | 11 chars | |
| user | `$` | 1-127 chars (user + realm at most 128) | **yes** (string-to-key salt) |
| realm | `$` | 1-127 chars (user + realm at most 128) | **yes** (string-to-key salt, uppercased) |
| checksum | `$` | 32 hex (16 bytes) | yes |
| edata2 | `$` | 64-40960 hex, a multiple of 16 | yes |

User plus realm may be at most 128 bytes together. Also accepts `$krb5tgs$3$*user$realm$spn*$checksum$edata2`; user and realm are taken from inside the block, and the line is printed back with the block intact.

The "checksum" field is the first two DES blocks of the ciphertext, not a MAC. A DES etype keeps its integrity check inside the plaintext, so the split exists only to keep the line shaped like the other TGS-REP modes.

The kernel derives the DES key from the candidate with the RFC 3961 string-to-key and decrypts with DES-CBC under a zero IV. It first decrypts only the block holding the ASN.1 header and tests for an `EncTicketPart` (tag `0x63`), with a second marker one block further in. When both hold, it decrypts the whole plaintext, zeroes the embedded 16-byte MD5, recomputes it and compares.

### Mode 39100: DES-CBC-CRC

**Module:** `module_39100.c`

```
$krb5tgs$1$user$realm$checksum$edata2
```

Same parser and limits as 38500 with the signature `$krb5tgs$1$`. Etype 1 uses the key itself as the CBC IV and a CRC-32 in place of the MD5: the kernel rejects early on the ASN.1 header of the second block, then decrypts everything and verifies the CRC-32.

---

## AS-REP Roast

### Mode 18200: RC4

**Module:** `module_18200.c`

```
$krb5asrep$23$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5asrep$` | | 11 chars | |
| etype `23` | `$` | 2 digits | |
| user | `$` | 0-511 chars | no |
| realm | `$` | 0-511 chars | no |
| checksum | `$` | 32 hex (16 bytes) | yes |
| edata2 | `$` | 64-40958 hex | yes |

Two other shapes load:

| Shape | Detected when |
|-------|---------------|
| `$krb5asrep$23$user@realm:checksum$edata2` (Impacket GetNPUsers) | `23$` is present and the line has a `:` |
| `$krb5asrep$user@realm:checksum$edata2` (no etype) | the signature is not followed by `23$` |

The canonical shape is chosen when `23$` is present and there is no `:`. In every shape the principal is a label; only checksum and edata2 are used.

---

### Mode 32100: AES128

**Module:** `module_32100.c`

```
$krb5asrep$17$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5asrep$17$` | | 14 chars | |
| user | `$` | 1-511 chars | **yes** (PBKDF2 salt) |
| realm | `$` | 1-511 chars | **yes** (PBKDF2 salt, uppercased) |
| checksum | `$` | 24 hex (12 bytes) | yes |
| edata2 | `$` | 64-40960 hex | yes |

#### Mode 32100: AES128 &mdash; JtR shape (checksum after edata2)

```
$krb5asrep$17$salt$edata2$checksum
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5asrep$17$` | | 14 chars | |
| salt | `$` | 1-511 chars | **yes** (PBKDF2 salt, used verbatim) |
| edata2 | `$` | 64-40960 hex | yes |
| checksum | `$` | 24 hex (12 bytes) | yes |

Detected when the character at `line_len - 25` is `$`: the checksum is always 24 hex, so a `$` at that offset means the checksum is the last field. The salt has to be the full `REALMuser` string already; nothing is uppercased. The line is printed back in this shape.

### Mode 32200: AES256

**Module:** `module_32200.c`

```
$krb5asrep$18$user$realm$checksum$edata2
$krb5asrep$18$salt$edata2$checksum
```

Same parser and limits as 32100, including the JtR shape. The key is 32 bytes.

### Mode 38600: DES-CBC-MD5

**Module:** `module_38600.c`

```
$krb5asrep$3$user$realm$checksum$edata2
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5asrep$3$` | | 13 chars | |
| user | `$` | 1-127 chars (user + realm at most 128) | **yes** (string-to-key salt) |
| realm | `$` | 1-127 chars (user + realm at most 128) | **yes** (string-to-key salt, uppercased) |
| checksum | `$` | 32 hex (16 bytes) | yes |
| edata2 | `$` | 64-40960 hex, a multiple of 16 | yes |

User plus realm may be at most 128 bytes together. Also accepts the joined shape `$krb5asrep$3$user@realm:checksum$edata2`, chosen when a `:` comes before the first `$`; the realm is what follows the last `@`.

Same check as 38500, except that the header test looks for an AS-REP or TGS-REP encrypted part (tags `0x79` and `0x7a`) and there is no second marker: one header block is tested, then the full MD5.

### Mode 39200: DES-CBC-CRC

**Module:** `module_39200.c`

```
$krb5asrep$1$user$realm$checksum$edata2
```

Same parser and limits as 38600, including the joined shape, with the signature `$krb5asrep$1$`. IV is the key and the integrity check is CRC-32, as in 39100.

---

## AS-REQ Pre-Auth

### Mode 7500: RC4

**Module:** `module_07500.c`

```
$krb5pa$23$user$realm$checksum$encrypted
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5pa$23$` | | 11 chars | |
| user | `$` | 0-511 chars | no |
| realm | `$` | 0-511 chars | no |
| checksum | `$` | 32 hex (16 bytes) | yes |
| encrypted | `$` | 58-76 hex | yes |

This is the shape KerbWolf writes: the HMAC-MD5 checksum first, then the encrypted timestamp, in wire order. Two other shapes load, both with the encrypted timestamp before the checksum:

| Shape | Data field |
|-------|------------|
| `$krb5pa$23$user$realm$salt$<encrypted><checksum>` (hashcat's original shape, also JtR's `krb5pa-md5`) | salt 0-255 chars, data 90-108 hex |
| `$krb5pa$23$user$realm$<encrypted><checksum>` (single field) | 90-108 hex |

The parser tries the salt shape first, then the split shape, then the single field. The salt is a label.

---

### Mode 19800: AES128

**Module:** `module_19800.c`

```
$krb5pa$17$user$realm$checksum$encrypted
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5pa$17$` | | 11 chars | |
| user | `$` | 1-511 chars | **yes** (PBKDF2 salt) |
| realm | `$` | 1-511 chars | **yes** (PBKDF2 salt, uppercased) |
| checksum | `$` | 24 hex (12 bytes) | yes |
| encrypted | `$` | 80-88 hex | yes |

This is the shape KerbWolf writes. Three other shapes load, all with the encrypted timestamp before the checksum in one 104-112 hex field:

| Shape | Salt used |
|-------|-----------|
| `$krb5pa$17$user$realm$<encrypted><checksum>` (single field) | `REALM + user` |
| `$krb5pa$17$user$realm$$<encrypted><checksum>` (empty salt, JtR) | `REALM + user` |
| `$krb5pa$17$user$realm$salt$<encrypted><checksum>` (explicit salt) | the salt field, verbatim, up to 513 chars |

The shape is picked by counting `$`. With six or more, the salt shapes are tried first; if that fails and there are exactly six, the split shape is tried. With fewer, the line is read as the single field.

The parser accepts an explicit salt of up to 1022 chars, but hashcat aborts with a buffer overflow when the salt is longer than 513 (it copies the salt into a 513-byte buffer to print the line back). 513 is the usable limit in both 19800 and 19900. In the explicit-salt shape the user and realm fields are labels.

### Mode 19900: AES256

**Module:** `module_19900.c`

```
$krb5pa$18$user$realm$checksum$encrypted
```

Same parser and limits as 19800 with the signature `$krb5pa$18$`. The key is 32 bytes.

### Mode 39000: DES-CBC-MD5

**Module:** `module_39000.c`

```
$krb5pa$3$user$realm$cipher
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5pa$3$` | | 10 chars | |
| user | `$` | 1-127 chars (user + realm at most 128) | **yes** (string-to-key salt) |
| realm | `$` | 1-127 chars (user + realm at most 128) | **yes** (string-to-key salt, uppercased) |
| cipher | `$` | 64-256 hex, a multiple of 16 | yes |

This is the shape KerbWolf writes: the whole PA-ENC-TIMESTAMP cipher in one field. The split shape `$krb5pa$3$user$realm$<32 hex>$<32-224 hex>`, with the first two blocks apart, also loads, and is the shape of hashcat's own example hash. User plus realm may be at most 128 bytes together.

The kernel decrypts the whole timestamp with DES-CBC under a zero IV, rejects early unless the plaintext at byte 24 opens a `SEQUENCE` (`0x30`), and verifies the embedded MD5 with its field zeroed.

### Mode 39300: DES-CBC-CRC

**Module:** `module_39300.c`

```
$krb5pa$1$user$realm$cipher
```

Same parser and limits as 39000 with the signature `$krb5pa$1$`. The kernel decrypts with the key as IV, requires a `SEQUENCE` tag at byte 12, verifies the CRC-32, and checks that the `GeneralizedTime` starts with `20` followed by digits.

---

## DB Key (extracted from NTDS.dit)

These modes hold no ciphertext. hashcat derives the key from the candidate password and compares it with the stored one. `tools/krb5db2hashcat.py` in the hashcat tree writes these lines from secretsdump, gosecretsdump, mimikatz, DSInternals and ntdissector output.

### Mode 28800: AES128 DB Key

**Module:** `module_28800.c`

```
$krb5db$17$user$realm$key
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5db$17$` | | 11 chars | |
| user | `$` | 1-511 chars | **yes** (PBKDF2 salt) |
| realm | `$` | 1-511 chars | **yes** (PBKDF2 salt, uppercased) |
| key | `$` | 32 hex (16 bytes) | yes |

Key derivation is PBKDF2-HMAC-SHA1 with 4096 iterations. Also accepts an optional `*spn*$` block before the key, which is dropped on output.

### Mode 28900: AES256 DB Key

**Module:** `module_28900.c`

```
$krb5db$18$user$realm$key
```

Same as 28800 with the signature `$krb5db$18$` and a 64-hex (32-byte) key.

### Mode 38400: DES DB Key

**Module:** `module_38400.c`

```
$krb5db$<1|2|3>$user$realm$key
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$krb5db$1$`, `$krb5db$2$` or `$krb5db$3$` | | 10 chars | |
| user | `$` | 1-127 chars (user + realm at most 128) | **yes** (string-to-key salt) |
| realm | `$` | 1-127 chars (user + realm at most 128) | **yes** (string-to-key salt, uppercased) |
| key | `$` | 16 hex (8 bytes) | yes |

User plus realm may be at most 128 bytes together. Also accepts an optional `*spn*$` block before the key, which is dropped on output.

The etype digit is kept only to print the line back. The DES string-to-key gives the same 8-byte key for etypes 1, 2 and 3, so an account's `$krb5db$1$` and `$krb5db$3$` lines hold the same key and count as one hash when loaded together.

---

## NT Hash Input

These three modes take the same lines as their password counterparts, but the candidates are 32-hex NT hashes instead of passwords. hashcat skips the MD4 step and uses each candidate directly as the RC4 key. Candidates must be exactly 32 characters, and the modes are left out of hash-mode autodetection, so `-m` has to be given.

### Mode 35300: TGS-REP, NT hash input

**Module:** `module_35300.c`

Same four line shapes as mode 13100.

### Mode 35400: AS-REP, NT hash input

**Module:** `module_35400.c`

Same three line shapes as mode 18200.

### Mode 39400: Pre-Auth, NT hash input

**Module:** `module_39400.c`

Takes the split shape `$krb5pa$23$user$realm$checksum$encrypted` and the salt shape `$krb5pa$23$user$realm$salt$<encrypted><checksum>` of mode 7500, but not the single field. The encrypted timestamp must be exactly 72 hex here, where 7500 allows 58-76.

---

## Timeroasting (MS-SNTP)

### Mode 31300: MS-SNTP (68-byte Authenticator)

**Module:** `module_31300.c`

```
$sntp-ms$<32hex_digest>$<96hex_salt>
```

| Field | Delimiter | Length | Used for cracking |
|-------|-----------|--------|-------------------|
| signature `$sntp-ms$` | | 9 chars | |
| MD5 digest | `$` | 32 hex | yes |
| salt (NTP response header) | `$` | 96 hex (48 bytes) | yes |

The hash is `MD5(NTOWFv1 || salt)` where NTOWFv1 is the NT hash (MD4 of the UTF-16LE password) and salt is the 48-byte NTP server response header.

The RID identifies the account but is not part of the hash string and is not used in the MD5. `kw-timeroast --rid-prefix` writes it, or the account name, in front of the line for account mapping.

### No module: MS-SNTP SHA512 (120-byte ExtendedAuthenticator)

hashcat has no mode for this format. KerbWolf writes it as:

```
$sntp-ms-sha512$<RID>$<128hex_digest>$<96hex_salt>
```

| Field | Length | Used for cracking |
|-------|--------|-------------------|
| RID | 1-10 digits | **yes** (KDF context input) |
| HMAC-SHA512 digest | 128 hex (64 bytes) | yes |
| salt (NTP response header) | 96 hex (48 bytes) | yes |

Unlike mode 31300, where the RID is a label, this format needs the RID to crack. It feeds the SP800-108 KDF as the Context parameter:

```
derived_key = KDF(SP800-108, PRF=HMAC-SHA512, Key=NTOWFv1,
    data = counter(4,BE) || "sntp-ms\0" || 0x00 || RID(4,LE) || 512(4,BE))
checksum = HMAC-SHA512(derived_key, salt)
```

---

## What hashcat actually needs to crack each hash

The hash line carries both cryptographic inputs and labels. Getting a label wrong breaks nothing. Getting a cryptographic input wrong means zero results with no error.

### RC4 modes (7500, 13100, 18200, 35300, 35400, 39400)

| Field | Role | Wrong value breaks cracking? |
|-------|------|------------------------------|
| checksum | Cryptographic: keys the RC4 decryption; 13100, 18200, 35300 and 35400 also verify it as the HMAC-MD5 | Yes |
| edata2 / encrypted | Cryptographic: ciphertext | Yes |
| user | Label | No |
| realm | Label | No |
| spn | Label | No |
| salt (7500, 39400) | Label | No |

RC4 key derivation is `MD4(UTF-16LE(password))`: no salt, no username, no realm. The labels exist so cracked results can be attributed back to accounts. The pre-auth modes 7500 and 39400 do not recompute the HMAC: they decrypt the timestamp and accept a candidate when the plaintext looks like one.

### AES modes (19600, 19700, 19800, 19900, 28800, 28900, 32100, 32200)

| Field | Role | Wrong value breaks cracking? |
|-------|------|------------------------------|
| checksum / stored key | Cryptographic: verification target | Yes |
| edata2 / encrypted | Cryptographic: ciphertext | Yes |
| user | **Cryptographic**: PBKDF2 salt component (case-sensitive); a label when the line carries an explicit salt | **Yes** |
| realm | **Cryptographic**: PBKDF2 salt component (uppercased by hashcat); a label when the line carries an explicit salt | **Yes** |
| explicit salt (JtR shapes) | **Cryptographic**: PBKDF2 salt, used verbatim | **Yes** |
| spn | Label | No |

Key derivation is `PBKDF2-HMAC-SHA1(password, REALM + user, 4096)` followed by the RFC 3962 key derivation. Wrong username case means a wrong salt, a wrong key, and silent failure.

### DES modes (38400, 38500, 38600, 39000, 39100, 39200, 39300)

| Field | Role | Wrong value breaks cracking? |
|-------|------|------------------------------|
| checksum + edata2 / cipher | Cryptographic: the DES-CBC ciphertext (38500, 38600, 39000, 39100, 39200, 39300) | Yes |
| stored key | Cryptographic: verification target (38400) | Yes |
| user | **Cryptographic**: string-to-key salt component | **Yes** |
| realm | **Cryptographic**: string-to-key salt component (uppercased by hashcat) | **Yes** |
| spn | Label | No |
| etype digit (38400) | Label: the key is the same for 1, 2 and 3 | No |

The DES string-to-key uses `REALM + user` as salt, same as AES. These modes take password candidates and run the string-to-key on each one; they do not search the 56-bit key space.

### Timeroast (31300)

| Field | Role | Wrong value breaks cracking? |
|-------|------|------------------------------|
| MD5 digest | Cryptographic: verification target | Yes |
| salt | Cryptographic: NTP response header fed to MD5 | Yes |

### Summary rule

**RC4: only the ciphertext matters.** Everything else is a label.
**AES and DES: the ciphertext and the username and realm matter.** They are the salt. Get them wrong and hashcat silently produces nothing.

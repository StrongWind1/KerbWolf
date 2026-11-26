# Hashcat Internals

Field-by-field breakdown of how hashcat parses each Kerberos hash mode, read from the `module_*.c` files of hashcat master (commit `16b164c15`, 2026-11-25) and checked by loading boundary-case lines into a build of that commit. Useful when a hash won't load or when you're building tooling that outputs these formats. Which fields affect cracking and which are only labels is on the [Troubleshooting](../troubleshooting.md#the-user-field-is-a-cryptographic-input) page.

hashcat has 21 Kerberos modes: 7500, 13100, 18200, 19600, 19700, 19800, 19900, 28800, 28900, 32100, 32200, 35300, 35400, 38400, 38500, 38600, 39000, 39100, 39200, 39300 and 39400. There is no mode for etypes 19 and 20 (AES-SHA2).

This page describes master, not the v8.0.0 release. Modes 39000 through 39400 were added after v8.0.0, and so was the `$user$realm$` layout of modes 7500, 13100, 18200, 19800, 19900, 35300, 35400 and 38500 (2026-11-04): in those eight modes v8.0.0 loads only the other shapes listed below.

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
| [39000](#mode-39000-des-cbc-md5) | AS-REQ Pre-Auth | 3 | `$krb5pa$3$user$realm$checksum$encrypted` | single field | **yes** |
| [39300](#mode-39300-des-cbc-crc) | AS-REQ Pre-Auth | 1 | `$krb5pa$1$user$realm$checksum$encrypted` | single field | **yes** |
| [28800](#mode-28800-aes128-db-key) | DB Key | 17 | `$krb5db$17$user$realm$key` | optional `*spn*` | **yes** |
| [28900](#mode-28900-aes256-db-key) | DB Key | 18 | `$krb5db$18$user$realm$key` | optional `*spn*` | **yes** |
| [38400](#mode-38400-des-db-key) | DB Key | 1, 2, 3 | <code>$krb5db$&lt;1&#124;2&#124;3&gt;$user$realm$key</code> | optional `*spn*` | **yes** |
| [35300](#mode-35300-tgs-rep-nt-hash-input) | TGS-REP (NT) | 23 | same as 13100 | same as 13100 | no |
| [35400](#mode-35400-as-rep-nt-hash-input) | AS-REP (NT) | 23 | same as 18200 | same as 18200 | no |
| [39400](#mode-39400-pre-auth-nt-hash-input) | AS-REQ Pre-Auth (NT) | 23 | same as 7500 | salt field only | no |
| [31300](#mode-31300-ms-sntp-68-byte-authenticator) | Timeroasting | MD5 | `$sntp-ms$digest$salt` | | no |

---

## Field limits

What each mode accepts in its canonical line. Every field is delimited by `$`. The other shapes a mode loads, and how hashcat tells them apart, are in the per-mode sections below.

| Mode | Prefix | User | Realm | Checksum | Data field |
|------|-----------|------|-------|----------|------------|
| 13100 | `$krb5tgs$23$` (12 chars) | 0-511 chars | 0-511 chars | 32 hex (16 bytes) | edata2, 64-40958 hex |
| 35300 | `$krb5tgs$23$` (12 chars) | 0-511 chars | 0-511 chars | 32 hex (16 bytes) | edata2, 64-40958 hex |
| 19600 | `$krb5tgs$17$` (12 chars) | 1-511 chars | 1-511 chars | 24 hex (12 bytes) | edata2, 64-40960 hex |
| 19700 | `$krb5tgs$18$` (12 chars) | 1-511 chars | 1-511 chars | 24 hex (12 bytes) | edata2, 64-40960 hex |
| 38500 | `$krb5tgs$3$` (11 chars) | 1-127 chars | 1-127 chars | 32 hex (16 bytes) | edata2, 64-40960 hex, a multiple of 16 |
| 39100 | `$krb5tgs$1$` (11 chars) | 1-127 chars | 1-127 chars | 32 hex (16 bytes) | edata2, 64-40960 hex, a multiple of 16 |
| 18200 | `$krb5asrep$23$` (14 chars) | 0-511 chars | 0-511 chars | 32 hex (16 bytes) | edata2, 64-40958 hex |
| 35400 | `$krb5asrep$23$` (14 chars) | 0-511 chars | 0-511 chars | 32 hex (16 bytes) | edata2, 64-40958 hex |
| 32100 | `$krb5asrep$17$` (14 chars) | 1-511 chars | 1-511 chars | 24 hex (12 bytes) | edata2, 64-40960 hex |
| 32100, JtR shape | `$krb5asrep$17$` (14 chars) | salt, 1-511 chars | none | 24 hex (12 bytes), after the data | edata2, 64-40960 hex |
| 32200 | `$krb5asrep$18$` (14 chars) | 1-511 chars | 1-511 chars | 24 hex (12 bytes) | edata2, 64-40960 hex |
| 32200, JtR shape | `$krb5asrep$18$` (14 chars) | salt, 1-511 chars | none | 24 hex (12 bytes), after the data | edata2, 64-40960 hex |
| 38600 | `$krb5asrep$3$` (13 chars) | 1-127 chars | 1-127 chars | 32 hex (16 bytes) | edata2, 64-40960 hex, a multiple of 16 |
| 39200 | `$krb5asrep$1$` (13 chars) | 1-127 chars | 1-127 chars | 32 hex (16 bytes) | edata2, 64-40960 hex, a multiple of 16 |
| 7500 | `$krb5pa$23$` (11 chars) | 0-511 chars | 0-511 chars | 32 hex (16 bytes) | encrypted, 58-76 hex |
| 39400 | `$krb5pa$23$` (11 chars) | 0-511 chars | 0-511 chars | 32 hex (16 bytes) | encrypted, 58-76 hex |
| 19800 | `$krb5pa$17$` (11 chars) | 1-511 chars | 1-511 chars | 24 hex (12 bytes) | encrypted, 80-88 hex |
| 19900 | `$krb5pa$18$` (11 chars) | 1-511 chars | 1-511 chars | 24 hex (12 bytes) | encrypted, 80-88 hex |
| 39000 | `$krb5pa$3$` (10 chars) | 1-127 chars | 1-127 chars | 32 hex (16 bytes) | encrypted, 32-224 hex; checksum plus encrypted a multiple of 16 |
| 39300 | `$krb5pa$1$` (10 chars) | 1-127 chars | 1-127 chars | 32 hex (16 bytes) | encrypted, 32-224 hex; checksum plus encrypted a multiple of 16 |
| 28800 | `$krb5db$17$` (11 chars) | 1-511 chars | 1-511 chars | none | key, 32 hex (16 bytes) |
| 28900 | `$krb5db$18$` (11 chars) | 1-511 chars | 1-511 chars | none | key, 64 hex (32 bytes) |
| 38400 | `$krb5db$1$`, `$krb5db$2$` or `$krb5db$3$` (10 chars) | 1-127 chars | 1-127 chars | none | key, 16 hex (8 bytes) |
| 31300 | `$sntp-ms$` (9 chars) | none | none | MD5 digest, 32 hex | salt (NTP response header), 96 hex (48 bytes) |
| No mode, `$sntp-ms-sha512$` | `$sntp-ms-sha512$` | RID, 1-10 digits | none | HMAC-SHA512 digest, 128 hex (64 bytes) | salt (NTP response header), 96 hex (48 bytes) |

In every DES mode (38400, 38500, 38600, 39000, 39100, 39200, 39300) user plus realm may be at most 128 bytes together. Modes 35300, 35400 and 39400 take 32-hex NT hashes as candidates, not passwords; that is described in [their own section](#nt-hash-input).

## Parser rules

- **An explicit salt field is used verbatim.** The JtR shapes of 32100/32200 (`salt$edata2$checksum`) and 19800/19900 (`user$realm$salt$data`) take the salt exactly as written, with no uppercasing.
- **DES modes cap the salt and the password.** User plus realm may be at most 128 bytes together, and candidate passwords at most 64 bytes.
- **DES ciphertext must be whole blocks.** The hex of the cipher has to be a multiple of 16 chars (8 bytes), or the line is rejected.
- **Hex fields accept both cases.** `a-f` and `A-F` both load; hashcat prints lowercase.
- **A `$` inside a field breaks the line.** Fields are split on `$`, so a user field that ends in `$`, as a machine account name does, shifts every field after it and the line is rejected with `Token length exception`. What to write instead is under [Correcting a line by hand](../troubleshooting.md#correcting-a-line-by-hand).

Which fields are cryptographic inputs and which are only labels, and what a wrong user or realm does to an AES or DES hash, is on the [Troubleshooting](../troubleshooting.md#the-user-field-is-a-cryptographic-input) page.

---

## TGS-REP Roast (Kerberoast)

### Mode 13100: RC4

**Module:** `module_13100.c`

```
$krb5tgs$23$user$realm$checksum$edata2
```

User and realm are labels and may be empty. Only checksum and edata2 matter: the checksum keys the RC4 decryption, and 13100, 18200, 35300 and 35400 also verify it as the HMAC-MD5. Three other shapes load:

| Shape | Detected when |
|-------|---------------|
| `$krb5tgs$23$*user$realm$spn*$checksum$edata2` (Rubeus, Impacket) | `23$` is followed by `*` |
| `$krb5tgs$23$checksum$edata2` (bare) | `23$` is followed by fewer than three more `$` |
| `$krb5tgs$spn:checksum$edata2` (JtR) | `$krb5tgs$` is not followed by `23$` |

The canonical shape is chosen when `23$` is followed by at least three more `$`. The `*...*` block may be up to 2046 chars (2047 counting the `$` that follows it), the JtR SPN 0-2047 chars.

---

### Mode 19600: AES128

**Module:** `module_19600.c`

```
$krb5tgs$17$user$realm$checksum$edata2
```

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

Two other shapes load:

| Shape | Detected when |
|-------|---------------|
| `$krb5asrep$23$user@realm:checksum$edata2` (Impacket GetNPUsers) | `23$` is present and the line has a `:` |
| `$krb5asrep$user@realm:checksum$edata2` (no etype) | `$krb5asrep$` is not followed by `23$` |

The canonical shape is chosen when `23$` is present and there is no `:`. In every shape the principal is a label; only checksum and edata2 are used.

A no-etype line whose principal opens with digits and a `$`, such as `$krb5asrep$3$user@realm:checksum$edata2`, is rejected: it is the joined shape of another etype. A `$` right before the `@`, as in `1234$@realm`, is still accepted.

---

### Mode 32100: AES128

**Module:** `module_32100.c`

```
$krb5asrep$17$user$realm$checksum$edata2
```

#### Mode 32100: AES128 &mdash; JtR shape (checksum after edata2)

```
$krb5asrep$17$salt$edata2$checksum
```

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

This is the shape KerbWolf writes: the HMAC-MD5 checksum first, then the encrypted timestamp, in wire order. Two other shapes load, both with the encrypted timestamp before the checksum:

| Shape | Data field |
|-------|------------|
| `$krb5pa$23$user$realm$salt$<encrypted><checksum>` (hashcat's original shape, also JtR's `krb5pa-md5`) | salt 0-255 chars, data 90-108 hex |
| `$krb5pa$23$user$realm$<encrypted><checksum>` (single field) | 90-108 hex |

The parser tries the salt shape first, then the split shape, then the single field. The salt is a label.

The pre-auth modes 7500 and 39400 do not recompute the HMAC: they decrypt the timestamp and accept a candidate when the plaintext looks like one.

---

### Mode 19800: AES128

**Module:** `module_19800.c`

```
$krb5pa$17$user$realm$checksum$encrypted
```

This is the shape KerbWolf writes. Three other shapes load, all with the encrypted timestamp before the checksum in one 104-112 hex field:

| Shape | Salt used |
|-------|-----------|
| `$krb5pa$17$user$realm$<encrypted><checksum>` (single field) | `REALM + user` |
| `$krb5pa$17$user$realm$$<encrypted><checksum>` (empty salt, JtR) | `REALM + user` |
| `$krb5pa$17$user$realm$salt$<encrypted><checksum>` (explicit salt) | the salt field, verbatim, up to 1022 chars |

The shape is picked by counting `$`. With six or more, the salt shapes are tried first; if that fails and there are exactly six, the split shape is tried. With fewer, the line is read as the single field.

An explicit salt may be up to 1022 chars in both 19800 and 19900; v8.0.0 takes 512. A build of master from between 2026-11-12 and 2026-11-23 accepts 1022 but aborts with a buffer overflow when the salt is longer than 513, because it copied the salt into a 513-byte buffer to print the line back. In the explicit-salt shape the user and realm fields are labels.

### Mode 19900: AES256

**Module:** `module_19900.c`

```
$krb5pa$18$user$realm$checksum$encrypted
```

Same parser and limits as 19800 with the signature `$krb5pa$18$`. The key is 32 bytes.

### Mode 39000: DES-CBC-MD5

**Module:** `module_39000.c`

```
$krb5pa$3$user$realm$checksum$encrypted
```

This is the shape KerbWolf writes and the shape of hashcat's own example hash: the first two blocks of the PA-ENC-TIMESTAMP cipher (32 hex), then the rest (32-224 hex). As in mode 38500, the "checksum" field is not a MAC; the split only gives the line the layout of the other modes. The whole cipher in one field, `$krb5pa$3$user$realm$<64-256 hex>`, also loads, and is what hashcat's test generator writes. User plus realm may be at most 128 bytes together.

The kernel first decrypts only the fourth block, DES-CBC under a zero IV, and rejects the candidate unless the plaintext at byte 24 opens a `SEQUENCE` (`0x30`). It then decrypts the whole timestamp and verifies the embedded MD5 with its field zeroed.

### Mode 39300: DES-CBC-CRC

**Module:** `module_39300.c`

```
$krb5pa$1$user$realm$checksum$encrypted
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

User plus realm may be at most 128 bytes together. Also accepts an optional `*spn*$` block before the key, which is dropped on output.

The etype digit is kept only to print the line back. The DES string-to-key gives the same 8-byte key for etypes 1, 2 and 3, so an account's `$krb5db$1$` and `$krb5db$3$` lines hold the same key and count as one hash when loaded together.

---

## NT Hash Input

These three modes take the same lines as their password counterparts, but the candidates are 32-hex NT hashes instead of passwords. hashcat skips the MD4 step and uses each candidate directly as the RC4 key. Candidates must be exactly 32 hex digits, in either case; anything else is skipped. The modes are left out of hash-mode autodetection, so `-m` has to be given.

### Mode 35300: TGS-REP, NT hash input

**Module:** `module_35300.c`

Same four line shapes as mode 13100.

### Mode 35400: AS-REP, NT hash input

**Module:** `module_35400.c`

Same three line shapes as mode 18200.

### Mode 39400: Pre-Auth, NT hash input

**Module:** `module_39400.c`

Takes the split shape `$krb5pa$23$user$realm$checksum$encrypted` and the salt shape `$krb5pa$23$user$realm$salt$<encrypted><checksum>` of mode 7500, but not the single field. The encrypted timestamp may be 58-76 hex, as in 7500; a build of master older than 2026-11-25 takes exactly 72.

---

## Timeroasting (MS-SNTP)

### Mode 31300: MS-SNTP (68-byte Authenticator)

**Module:** `module_31300.c`

```
$sntp-ms$<32hex_digest>$<96hex_salt>
```

The hash is `MD5(NTOWFv1 || salt)` where NTOWFv1 is the NT hash (MD4 of the UTF-16LE password) and salt is the 48-byte NTP server response header.

The RID identifies the account but is not part of the hash string and is not used in the MD5. `kw-timeroast --rid-prefix` writes it, or the account name, in front of the line for account mapping.

### No module: MS-SNTP SHA512 (120-byte ExtendedAuthenticator)

hashcat has no mode for this format. KerbWolf writes it as:

```
$sntp-ms-sha512$<RID>$<128hex_digest>$<96hex_salt>
```

Unlike mode 31300, where the RID is a label, this format needs the RID to crack. It feeds the SP800-108 KDF as the Context parameter:

```
derived_key = KDF(SP800-108, PRF=HMAC-SHA512, Key=NTOWFv1,
    data = counter(4,BE) || "sntp-ms\0" || 0x00 || RID(4,LE) || 512(4,BE))
checksum = HMAC-SHA512(derived_key, salt)
```

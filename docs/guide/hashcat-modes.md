# Hashcat Mode Reference

All 29 hashcat modes for Windows Kerberos encryption types. Mode numbers and hash prefixes for every combination of attack type and etype.

## Mode Matrix

|  | DES-CBC-CRC (1) | DES-CBC-MD5 (3) | AES128-SHA1 (17) | AES256-SHA1 (18) | AES128-SHA2 (19) | AES256-SHA2 (20) | RC4 (23) |
|---|---|---|---|---|---|---|---|
| **TGS-REP** | 39100 `$krb5tgs$1$` | 38500 `$krb5tgs$3$` | 19600 `$krb5tgs$17$` | 19700 `$krb5tgs$18$` | 39400 `$krb5tgs$19$` | 39500 `$krb5tgs$20$` | 13100 `$krb5tgs$23$` |
| **AS-REP** | 39200 `$krb5asrep$1$` | 38600 `$krb5asrep$3$` | 32100 `$krb5asrep$17$` | 32200 `$krb5asrep$18$` | 39600 `$krb5asrep$19$` | 39700 `$krb5asrep$20$` | 18200 `$krb5asrep$23$` |
| **Pre-Auth** | 39300 `$krb5pa$1$` | 39000 `$krb5pa$3$` | 19800 `$krb5pa$17$` | 19900 `$krb5pa$18$` | 39800 `$krb5pa$19$` | 39900 `$krb5pa$20$` | 7500 `$krb5pa$23$` |
| **DB Key** | 38400 `$krb5db$1$` | 38400 `$krb5db$3$` | 28800 `$krb5db$17$` | 28900 `$krb5db$18$` | 39010 `$krb5db$19$` | 39020 `$krb5db$20$` | -- |

### NT-Hash Variants (etype 23 only)

Same hash format as the password modes, but the input is a 32-char NT hash instead of a password.

| Attack | NT Mode | Password Mode |
|---|---|---|
| TGS-REP | 35300 | 13100 |
| AS-REP | 35400 | 18200 |
| Pre-Auth | 35700 | 7500 |

## Hash Formats

### Canonical Format

All etypes use the same field layout. This is what hashcat emits and what KerbWolf outputs.

**TGS-REP / AS-REP (enc-part hashes):**

```
$krb5tgs$<etype>$<user>$<realm>$<checksum_hex>$<edata2_hex>
$krb5asrep$<etype>$<user>$<realm>$<checksum_hex>$<edata2_hex>
```

**Pre-Auth (encrypted timestamp):**

```
$krb5pa$<etype>$<user>$<realm>$<data_hex>
```

**DB Key (stored key from KDC database):**

```
$krb5db$<etype>$<user>$<realm>$<key_hex>
```

### Checksum Sizes

| Etype | Hex chars | Bytes | Algorithm |
|---|---|---|---|
| 1, 3 (DES) | 32 | 16 | First 2 DES blocks (split point for early reject) |
| 17, 18 (AES-SHA1) | 24 | 12 | HMAC-SHA1-96 (RFC 3962) |
| 19 (AES128-SHA2) | 32 | 16 | HMAC-SHA256-128 (RFC 8009) |
| 20 (AES256-SHA2) | 48 | 24 | HMAC-SHA384-192 (RFC 8009) |
| 23 (RC4) | 32 | 16 | HMAC-MD5 (RFC 4757) |

### Field Roles

| Field | RC4 (23) | All other etypes |
|---|---|---|
| `etype` | Required (selects crypto) | Required |
| `user` | Metadata only | Required (case-sensitive, part of salt) |
| `realm` | Metadata only | Required (uppercased, part of salt) |
| `checksum` | Required, 32 hex | Required, size varies by etype |
| `edata2` | Required | Required |

The SPN is not in the canonical format. It is operational metadata that does not feed any crypto. KerbWolf emits it in log output alongside the hash.

### Legacy Accepted Formats

hashcat accepts these on input and silently converts to canonical on output.

| Etype | TGS-REP legacy | AS-REP legacy |
|---|---|---|
| 23 | `$krb5tgs$23$*user$realm$spn*$checksum$edata2` (Rubeus) | `$krb5asrep$23$user@realm:checksum$edata2` (Impacket) |
| 23 | `$krb5tgs$23$checksum$edata2` (bare) | `$krb5asrep$user@realm:checksum$edata2` (no etype) |
| 23 | `$krb5tgs$spn:checksum$edata2` (JtR) | |
| 17, 18 | `$krb5tgs$E$user$realm$*spn*$checksum$edata2` | `$krb5asrep$E$salt$edata2$checksum` (JtR, fields reordered) |
| 19, 20 | `$krb5tgs$E$user$realm$*spn*$checksum$edata2` | (none) |

Pre-Auth legacy: `$krb5pa$E$user$realm$$data` (empty salt field) and `$krb5pa$E$user$realm$salt$data` (JtR explicit salt).

DB Key legacy: `$krb5db$E$user$realm$*spn*$key` (with SPN).

## Attack Types

| Attack | Source | Description |
|---|---|---|
| **TGS-REP** (Kerberoast) | TGS-REP `enc-part` | Service ticket encrypted with the service account's long-term key |
| **AS-REP** (AS-REP Roast) | AS-REP `enc-part` | Response to accounts with pre-auth disabled, encrypted with the client's key |
| **Pre-Auth** (AS-REQ) | `PA-ENC-TIMESTAMP` | Encrypted timestamp from pre-authentication, captured from network traffic |
| **DB Key** | `supplementalCredentials` / NTDS.dit | Long-term key stored in the KDC database |
| **NT-Hash variants** | Same ciphertext as RC4 modes | Cracks the NT hash directly instead of the password (etype 23 only) |

Mode 38400 handles etypes 1 and 3 in one module (same DES string-to-key). RC4 DB key is the NT hash itself (mode 1000).

## Encryption Type Details

| Etype | IANA Name | Key Derivation | Cipher | Integrity | RFC | Status |
|---|---|---|---|---|---|---|
| 1 | des-cbc-crc | DES string-to-key | DES-CBC (IV=key) | CRC32 | 3961 | Deprecated |
| 3 | des-cbc-md5 | DES string-to-key | DES-CBC (IV=0) | MD5 | 3961 | Deprecated |
| 17 | aes128-cts-hmac-sha1-96 | PBKDF2-SHA1 + nfold DK | AES-128-CTS | HMAC-SHA1-96 | 3962 | |
| 18 | aes256-cts-hmac-sha1-96 | PBKDF2-SHA1 + nfold DK | AES-256-CTS | HMAC-SHA1-96 | 3962 | |
| 19 | aes128-cts-hmac-sha256-128 | PBKDF2-SHA256 + SP800-108 | AES-128-CTS | HMAC-SHA256-128 | 8009 | |
| 20 | aes256-cts-hmac-sha384-192 | PBKDF2-SHA384 + SP800-108 | AES-256-CTS | HMAC-SHA384-192 | 8009 | |
| 23 | rc4-hmac | MD4 (NT hash) | RC4 | HMAC-MD5 | 4757 | Deprecated |

## Windows SHA2 Key Derivation

Windows Server 2025 implements RFC 8009 with these parameters:

1. **Salt**: `etype_name + \x00 + REALM + username` (e.g., `aes256-cts-hmac-sha384-192\x00SNOW.LABAdministrator`)
2. **PBKDF2**: 4096 iterations (not RFC 8009 default 32768)
3. **KDF-HMAC-SHA2**: SP 800-108 Counter Mode with label `kerberos`
4. **Subkey derivation**: `Ke = KDF(base_key, usage || 0xAA)`, `Ki = KDF(base_key, usage || 0x55)`

The 4096 iteration count is a Windows-specific deviation from the RFC 8009 specification. KerbWolf and hashcat (with the kerberos-complete branch) both implement this Windows-specific behavior.

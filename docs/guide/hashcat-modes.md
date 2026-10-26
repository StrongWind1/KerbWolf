# Hashcat Mode Reference

All 29 hashcat modes for Windows Kerberos encryption types. Mode numbers and hash prefixes for every combination of attack type and etype.

## Mode Matrix

|  | DES-CBC-CRC (1) | DES-CBC-MD5 (3) | AES128-SHA1 (17) | AES256-SHA1 (18) | AES128-SHA2 (19) | AES256-SHA2 (20) | RC4 (23) |
|---|---|---|---|---|---|---|---|
| **TGS-REP** | 39100 | 38500 | 19600 | 19700 | 39400 | 39500 | 13100 |
| **AS-REP** | 39200 | 38600 | 32100 | 32200 | 39600 | 39700 | 18200 |
| **Pre-Auth** | 39300 | 39000 | 19800 | 19900 | 39800 | 39900 | 7500 |
| **DB Key** | 38400 | 38400 | 28800 | 28900 | 39010 | 39020 | -- |

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

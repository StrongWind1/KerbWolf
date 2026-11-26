# Common options

Behaviour shared by more than one command: who needs credentials, how the domain controller is found, how LDAP discovery picks targets, and how `-e` is honoured. Each command page covers only what is specific to that tool.

## What each tool needs

|  | `kw-roast` | `kw-asrep` | `kw-timeroast` | `kw-extract` | `kw-tgt` |
|---|---|---|---|---|---|
| **Talks to** | KDC, port 88 | KDC, port 88 | NTP, UDP port 123 | Nothing, reads captures | KDC, port 88 |
| **Credentials** | Required, except with `--no-preauth` | Not for the attack | Not for a RID scan | None | Required |
| **Credential types** | Password, NT hash, ccache | Password, NT hash, ccache, for LDAP only | Password, NT hash, ccache, for LDAP only | None | Password, NT hash, per-etype key |
| **LDAP discovery** | `--ldap`, `--ldap-all` | `--ldap`, `--ldap-all` | `--ldap` | No | No |
| **Finds the DC** | DNS and flags | DNS and flags | No lookup, the DC is an argument | No DC | DNS and flags |
| **IPv6** | Yes | Yes | No, IPv4 only | Yes | Yes |
| **Encryption types** | Five, chosen with `-e` | Five, chosen with `-e` | Not Kerberos | All seven, whatever the capture holds | Five, chosen with `-e` or a key flag |
| **Existing output file** | Kept | Kept | Kept | Kept | Replaced |

## Authentication

| Method | Flags | Accepted by | Notes |
|---|---|---|---|
| **Password** | `-u admin -p pass` | `kw-roast`, `kw-asrep`, `kw-timeroast`, `kw-tgt` | Most common |
| **NT hash** | `-u admin -H :aabbccdd...` | `kw-roast`, `kw-asrep`, `kw-timeroast`, `kw-tgt` | Written as `LM:NT`, `:NT` or `NT`. Pass-the-hash for LDAP |
| **Kerberos ccache** | `-k -c admin.ccache` | `kw-roast`, `kw-asrep`, `kw-timeroast` | Pass-the-ticket. LDAP binds go through GSSAPI/SASL and need the [Kerberos setup](../installation.md#kerberos-setup) |
| **Per-etype key** | `--rc4-key`, `--aes256-key`, `--aes128-key`, `--des-md5-key`, `--des-crc-key` | `kw-tgt` | Pass-the-key |

What the credentials are used for differs by tool. `kw-roast` uses them to get a TGT (or takes the TGT from the ccache) and to bind to LDAP. `kw-asrep` and `kw-timeroast` send their attack without any; credentials there are only for the LDAP bind behind `--ldap`. `kw-tgt` uses them to request the TGT it saves.

In `kw-roast` and `kw-asrep`, `-d` and `-u` are optional with `-k -c`: the domain and username are read from the ccache. The ccache can also come from `KRB5CCNAME`.

## Finding the domain controller

`kw-roast`, `kw-asrep` and `kw-tgt` work out the DC's address and hostname from DNS and from the flags. `kw-timeroast` takes the DC as a positional argument and does no lookup.

| Value | Taken from, first match wins | If nothing matches |
|---|---|---|
| **Domain and user** | 1. `-d` and `-u`<br>2. The principal in the ccache, with `-k` and `-c` or `KRB5CCNAME` | Error: `-d` is required |
| **DC address** | 1. `--dc-ip`, when it is an IP address<br>2. `--dc-ip`, when it is a hostname that resolves<br>3. The target of the `_kerberos._tcp.DOMAIN` SRV record, when that target resolves<br>4. The A or AAAA record of the domain name | Error: use `--dc-ip` |
| **DC hostname** | 1. `--dc-hostname`, which always wins<br>2. `--dc-ip`, when it is a hostname<br>3. The SRV target | Unset: only the address is known |
| **Host in the SPN of a Kerberos LDAP bind** | 1. The DC hostname from the row above<br>2. `dnsHostName` from an anonymous RootDSE lookup<br>3. The domain name | Always has a value |

The SRV lookup runs first and the flags then override what it found. A hostname given to `--dc-ip` that does not resolve is an error only when the SRV record gave no address either.

!!! warning "Kerberos LDAP needs a hostname"
    GSSAPI authentication constructs an SPN like `ldap/DC01.corp.local`. If KerbWolf only has a DC IP (no hostname from SRV or `--dc-hostname`), it works down the last row of the table. If the bind is then refused, pass `--dc-hostname` explicitly.

## LDAP target discovery

`kw-roast`, `kw-asrep` and `kw-timeroast` can query LDAP for their targets instead of taking a list. LDAP needs an authenticated bind first, with any method from the [table above](#authentication).

| Command | Flag | Returns | What happens next |
|---|---|---|---|
| `kw-roast` | `--ldap` | Enabled, non-computer accounts with a `servicePrincipalName`, such as `svc_sql`, `svc_http`, `svc_backup` | One ticket request per account |
| `kw-roast` | `--ldap-all` | Every enabled user | A ticket request for every user. The KDC refuses a ticket for an account with no SPN, so those are skipped: against a lab DC the spray returned exactly the accounts `--ldap` finds |
| `kw-asrep` | `--ldap` | Enabled, non-computer accounts with the `DONT_REQUIRE_PREAUTH` flag (UAC bit 4194304) | One AS-REQ per account. If you see zero results, no enabled, non-computer account that your bind user can see has the flag |
| `kw-asrep` | `--ldap-all` | Every enabled user | An AS-REQ for every user. The KDC itself tells you which accounts don't require pre-auth by returning an AS-REP instead of a `PREAUTH_REQUIRED` error. Accounts that do require pre-auth are silently skipped |
| `kw-timeroast` | `--ldap` | Computer and gMSA accounts, with no disabled-account exclusion: RIDs from `objectSid`, names from sAMAccountName | One NTP request per RID. The NTP probe determines what responds. Trust accounts are not in the filter and need a RID scan |

The filters, as sent:

```
# kw-roast --ldap
(&(servicePrincipalName=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))

# kw-asrep --ldap
(&(UserAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))

# kw-roast --ldap-all, kw-asrep --ldap-all
(&(objectCategory=person)(objectClass=user)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))

# kw-timeroast --ldap
(|(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))
```

Add `--ldap-ssl` to use LDAPS on port 636 instead of LDAP on port 389.

!!! note "Paged searches for large domains"
    All LDAP queries use paged search (1000 results per page) to handle domains with thousands of accounts. The query runs to completion before any attacks begin.

## Encryption type selection

`kw-roast`, `kw-asrep` and `kw-tgt` take `-e` with one or more of `des-cbc-crc`, `des-cbc-md5`, `rc4`, `aes128` and `aes256`, repeated or comma-separated, in preference order. The default is `rc4`. AES-SHA2 (etypes 19 and 20) cannot be requested; those hashes come from `kw-extract`, which formats any etype 19 or 20 message it finds in a capture.

For `kw-roast` and `kw-asrep` the list is a request, not a guarantee:

- **The KDC chooses.** It picks the etype from the etypes in the request and the keys and settings of the account, so a hash can come back with a different etype than the first one given to `-e`. The hash is labelled with the etype that came back.
- **Nothing is issued when no etype fits.** A request the KDC cannot satisfy returns no ticket and the target is skipped: against a Server 2022 lab DC, `-e rc4` for an account limited to AES256 (`0x10`) produced nothing. What an account allows is in its [`msDS-SupportedEncryptionTypes`](../background/encryption-types.md#msds-supportedencryptiontypes).

`kw-tgt` uses `-e` differently, to pick the key it pre-authenticates with; see [kw-tgt](kw-tgt.md#behaviour).

## Transport

- **TCP and UDP.** `--transport` selects the Kerberos transport and defaults to `tcp`. With `udp`, a reply that is too large makes the request fall back to TCP automatically.
- **Timeout.** `--timeout` is the network timeout in seconds, 10 by default.
- **IPv4 and IPv6.** Both work for Kerberos requests, DC resolution and pcap parsing. `kw-timeroast` sends over IPv4 only.
- **DNS.** DC discovery uses the SRV record first, then A/AAAA.

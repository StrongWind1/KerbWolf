# kw-tgt

Request a Kerberos TGT using password, hash, or key (pass-the-key). Saves a ccache file for use with `kw-roast -k -c` or any tool that reads `KRB5CCNAME`.

For a full explanation of credential types and etype auto-detection, see the [guide](../guide/index.md) and [encryption types](../guide/encryption-types.md).

## Help

```
$ kw-tgt -h
usage: kw-tgt [-h] [--version] [-v] -d DOMAIN -u USER
              (-p PASS | -H HASH | --rc4-key HEX | --aes256-key HEX |
               --aes128-key HEX | --des-md5-key HEX | --des-crc-key HEX)
              [--dc-ip IP] [--dc-hostname HOST] [--transport {tcp,udp}]
              [--timeout TIMEOUT]
              [-e {des-cbc-crc,des-cbc-md5,rc4,aes128,aes256}] [-o FILE]

Request a Kerberos TGT using password, hash, or key (pass-the-key).

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Increase verbosity (-v, -vv)

target (required):
  -d DOMAIN, --domain DOMAIN
                        Domain FQDN
  -u USER, --user USER  Username (sAMAccountName)

credential (one required):
  -p PASS, --password PASS
                        Cleartext password
  -H HASH, --hashes HASH
                        NTLM hash — LM:NT, :NT, or NT (implies -e rc4)
  --rc4-key HEX         RC4 key / NT hash — 32 hex (implies -e rc4)
  --aes256-key HEX      AES-256 key — 64 hex (implies -e aes256)
  --aes128-key HEX      AES-128 key — 32 hex (implies -e aes128)
  --des-md5-key HEX     DES-CBC-MD5 key — 16 hex (implies -e des-cbc-md5)
  --des-crc-key HEX     DES-CBC-CRC key — 16 hex (implies -e des-cbc-crc)

connection:
  --dc-ip IP            DC IP or hostname (resolved via DNS SRV if omitted)
  --dc-hostname HOST    DC FQDN for Kerberos SPN (auto-detected if omitted)
  --transport {tcp,udp}
                        Transport protocol (default: tcp)
  --timeout TIMEOUT     Network timeout in seconds (default: 10)

output:
  -e {des-cbc-crc,des-cbc-md5,rc4,aes128,aes256}, --enctype {des-cbc-crc,des-cbc-md5,rc4,aes128,aes256}
                        Encryption type (auto-detected from key, default: rc4)
  -o FILE, --output FILE
                        Output ccache file (default: <user>.ccache)
```

## Examples

```bash
# Password
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!'

# NT hash (overpass-the-hash)
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -H :7facdc498ed1680c4fd1448319a8c04f

# AES256 key (pass-the-key)
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin --aes256-key <64hex>

# Password with AES256 authentication
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!' -e aes256

# Then use the TGT
kw-roast -k -c admin.ccache --ldap
```

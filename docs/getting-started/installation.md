# Installation

## What you need

- Python 3.11 or later (up to 3.14)
- A network path to a Kerberos KDC (Domain Controller)
- System Kerberos libraries (`libkrb5-dev` on Debian/Ubuntu, `krb5-devel` on RHEL)

## Install from source

```bash
git clone https://github.com/StrongWind1/KerbWolf.git
cd kerbwolf
pip install .
```

## Install with uv

```bash
uv tool install .
```

## Development install

```bash
uv sync
```

This installs all dev dependencies (pytest, ruff, ty) and creates a virtual environment.

## Verify installation

```bash
kw-roast --version
kw-asrep --version
kw-extract --version
kw-tgt --version
kw-timeroast --version
```

All five commands should print `kw-<tool> 0.1.0`.

## Run checks

```bash
make check    # lint + typecheck + tests
make docs     # build documentation
```

Or individually:

```bash
uv run ruff check            # linter (all rules enabled)
uv run ruff format --check   # formatter
uv run ty check              # type checker (strictest settings)
uv run pytest                # 693 unit tests
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| impacket | >= 0.13 | Kerberos protocol: ASN.1 structures, crypto, key derivation, CCache |
| ldap3 | >= 2.9.1 | LDAP enumeration with paging, NTLM and Kerberos auth |
| gssapi | >= 1.11 | GSSAPI/SASL for Kerberos-authenticated LDAP connections |
| dnspython | >= 2.4 | DNS SRV record lookup for DC discovery |

### Transitive dependencies

| Package | Comes from | Purpose |
|---------|-----------|---------|
| pyasn1 | impacket | ASN.1 DER encoding/decoding |
| pycryptodome | impacket | DES, AES, RC4, MD4 cryptographic primitives |

## Kerberos setup

When using Kerberos authentication (`-k -c ccache`), the system Kerberos library needs a `/etc/krb5.conf` file. The easiest way to generate it:

```bash
# Generate krb5.conf and /etc/hosts from the DC
nxc smb <DC_IP> --generate-krb5-file /etc/krb5.conf
nxc smb <DC_IP> --generate-hosts-file /etc/hosts
```

Alternatively, point DNS at the DC so SRV records resolve automatically:

```bash
echo "nameserver <DC_IP>" > /etc/resolv.conf
```

## Tools provided

| Command | Description |
|---------|-------------|
| `kw-roast` | TGS-REP Roast (Kerberoast) — request service tickets and extract hashes |
| `kw-asrep` | AS-REP Roast — extract hashes from accounts without pre-authentication |
| `kw-extract` | Extract Kerberos, SNTP, and NTLM hashes from pcap/pcapng captures |
| `kw-tgt` | Request a TGT using password, hash, or key (pass-the-key) |
| `kw-timeroast` | Timeroasting (MS-SNTP) — extract SNTP hashes for computer/trust accounts |

## Disclaimer

KerbWolf is intended for authorized penetration testing, red team engagements, and security audits only. You must have explicit written permission from the system owner before attacking any Active Directory environment.

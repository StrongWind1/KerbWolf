# Installation

## What you need

- Python 3.11 or later (up to 3.14)
- A network path to a Kerberos KDC (Domain Controller)
- System Kerberos libraries (`libkrb5-dev` on Debian/Ubuntu, `krb5-devel` on RHEL)

## Install from source

```bash
git clone https://github.com/StrongWind1/KerbWolf.git
cd KerbWolf
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

This installs all dev dependencies (pytest, ruff, ty, pre-commit) and creates a virtual environment.

## Verify installation

```bash
kw-roast --version
kw-asrep --version
kw-extract --version
kw-tgt --version
kw-timeroast --version
```

Each command prints its name and the installed package version, for example `kw-roast 1.1.0`.

## Run checks

```bash
make check    # lint + typecheck + tests + strict docs build
make docs     # build documentation
```

Or individually:

```bash
uv run ruff check                          # linter (all rules, minus the ignores in pyproject.toml)
uv run ruff format --check                 # formatter
uv run ty check                            # type checker
uv run pytest                              # unit tests
uv run --group docs mkdocs build --strict  # docs build, as `make check` runs it
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| impacket | >= 0.13 | Kerberos protocol: ASN.1 structures, crypto, key derivation, CCache |
| gssapi | >= 1.11.1 | GSSAPI/SASL for Kerberos-authenticated LDAP connections |
| dnspython | >= 2.4 | DNS SRV record lookup for DC discovery |
| pyasn1 | >= 0.4.6 | ASN.1 DER encoding/decoding |
| pycryptodomex | any | DES, AES, RC4, MD4 cryptographic primitives |

KerbWolf uses its own vendored copy of ldap3 (`kerbwolf/_vendor/ldap3/`) and does not declare ldap3 as a dependency. impacket pulls in the PyPI ldap3 as well; KerbWolf does not import that one.

## Kerberos setup

When using Kerberos authentication (`-k -c ccache`), LDAP binds go through GSSAPI, and the system Kerberos library has to be able to find the KDC for the realm. Without that the bind fails with `Cannot find KDC for realm`. Ticket requests themselves do not use the system library, so `kw-roast -k -c` with sAMAccountName targets and `--dc-ip` works without it. The easiest way to generate `/etc/krb5.conf`:

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
| `kw-extract` | Extract Kerberos, SNTP, NTLM, and LDAP simple-bind credentials from pcap/pcapng captures |
| `kw-tgt` | Request a TGT using password, hash, or key (pass-the-key) |
| `kw-timeroast` | Timeroasting (MS-SNTP) — extract SNTP hashes for computer, gMSA, and trust accounts |

## Disclaimer

KerbWolf is intended for authorized penetration testing, red team engagements, and security audits only. You must have explicit written permission from the system owner before attacking any Active Directory environment.

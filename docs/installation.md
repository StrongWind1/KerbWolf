# Installation

## What you need

- Python 3.11 or later (up to 3.14)
- A network path to a Kerberos KDC (Domain Controller)
- System Kerberos libraries (`libkrb5-dev` on Debian/Ubuntu, `krb5-devel` on RHEL)

## Install

From [PyPI](https://pypi.org/project/kerbwolf/):

```bash
uv tool install kerbwolf        # recommended
pip install kerbwolf             # or with pip
```

From source:

```bash
git clone https://github.com/StrongWind1/KerbWolf.git
cd KerbWolf
pip install .                    # or: uv tool install .
```

## Verify installation

```bash
kw-roast --version
kw-asrep --version
kw-extract --version
kw-tgt --version
kw-timeroast --version
```

Each command prints its name and the installed package version, for example `kw-roast 2.0.0`.

## Kerberos setup

When using Kerberos authentication (`-k -c ccache`), LDAP binds go through GSSAPI, and the system Kerberos library has to be able to find the KDC for the realm. Without that the bind fails with `Cannot find KDC for realm`. Ticket requests themselves do not use the system library, so `kw-roast -k -c` with sAMAccountName targets and `--dc-ip` works without it.

Either of these gives the library what it needs. Generate `/etc/krb5.conf` and `/etc/hosts` from the DC:

```bash
nxc smb <DC_IP> --generate-krb5-file /etc/krb5.conf
nxc smb <DC_IP> --generate-hosts-file /etc/hosts
```

Or point DNS at the DC so SRV records resolve automatically:

```bash
echo "nameserver <DC_IP>" > /etc/resolv.conf
```

How the tools themselves find the DC, and which hostname a Kerberos LDAP bind uses, is under [Finding the domain controller](commands/common-options.md#finding-the-domain-controller).

## Development

### Development install

```bash
uv sync
```

This installs all dev dependencies (pytest, ruff, ty, pre-commit) and creates a virtual environment.

### Run checks

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

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| impacket | >= 0.13 | Kerberos protocol: ASN.1 structures, crypto, key derivation, CCache |
| gssapi | >= 1.11.1 | GSSAPI/SASL for Kerberos-authenticated LDAP connections |
| dnspython | >= 2.4 | DNS SRV record lookup for DC discovery |
| pyasn1 | >= 0.4.6 | ASN.1 DER encoding/decoding |
| pycryptodomex | any | DES, AES, RC4, MD4 cryptographic primitives |

KerbWolf uses its own vendored copy of ldap3 (`kerbwolf/_vendor/ldap3/`) and does not declare ldap3 as a dependency. impacket pulls in the PyPI ldap3 as well; KerbWolf does not import that one.

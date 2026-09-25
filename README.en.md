# Quantum Ready

[Español](README.md) · **English**

Tools to prepare an infrastructure for post-quantum cryptography:

1. **Crypto-agility scanner** — finds, in configuration files and certificates,
   the algorithms a quantum computer will break (or weaken), and prioritises
   them by each service's exposure and reach.
2. **Hybrid key exchange** — a simulation of ML-KEM-768 + X25519 using the
   roles and ordering of the X25519MLKEM768 standard (TLS 1.3).
3. **Network impact** — measures, over real TCP, the byte and time cost of
   X25519, ML-KEM-768 and hybrid key exchange under different latency profiles.

The tool's output, command-line options and file names are in Spanish.

## Phase 1 — Crypto-agility scanner

### Usage

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
# .venv/bin/python -m pip install -r requirements.txt     # Linux/macOS

# Scan everything listed in the inventory
python -m quantum_ready -i ejemplos/inventario.yaml

# Scan specific paths (matched to their inventory service when there is one)
python -m quantum_ready ejemplos/bastion ejemplos/vpn/wg0.conf -i ejemplos/inventario.yaml

# Options
#   -o informe.json          JSON output file ('-' = standard output)
#   --nivel-minimo Medio     detail findings from this risk level up (default Alto)
```

Without `-i`, `./inventario.yaml` is used if present. Files that belong to no
service are still scanned, but their combined risk is left **unevaluated**: the
scanner never guesses exposure or reach.

### Supported formats

| Format | What is analysed |
|---|---|
| `sshd_config` / `ssh_config` | KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms, PubkeyAccepted*, CASignatureAlgorithms, HostKey |
| nginx | ssl_protocols, ssl_ciphers, ssl_ecdh_curve, ssl_conf_command |
| Apache | SSLProtocol (resolves `all -X`), SSLCipherSuite, SSLOpenSSLConfCmd |
| strongSwan (`ipsec.conf`, `swanctl.conf`) | ike/esp/proposals, authby/leftauth/rightauth |
| WireGuard (`wg*.conf`) | PresharedKey per `[Peer]` |
| Certificates (`.pem`, `.crt`, `.cer`, `.der`) | public key (type and size) and signature (algorithm and hash), multi-block chains |

The format is detected from the file name and, when that is not enough, from
the content.

### Rulebook

All classifications live in [quantum_ready/reglas.py](quantum_ready/reglas.py):
`ALGORITMOS` (category, recommendation and rationale) and `PATRONES` (how each
name is recognised). Notable rules:

- **Hybrids first.** `mlkem768x25519-sha256`, `sntrup761x25519-sha512`,
  `X25519MLKEM768`… are checked before any substring and stop the search, so
  they are not flagged 🔴 for containing `x25519`. In IPsec, a proposal with
  ML-KEM plus a classical key exchange counts as hybrid.
- **CBC mode.** Any cipher in CBC mode (explicit, or implicit in OpenSSL names
  without GCM/CCM such as `ECDHE-RSA-AES128-SHA256`) becomes ⚪ Obsolete.
- **WireGuard.** Peer without PresharedKey → 🔴 Critical; with PresharedKey →
  🟡 Warning, with the reasoning explained in the report.

Categories: 🔴 Critical (broken by Shor) · 🟡 Warning (weakened by Grover) ·
⚪ Obsolete (broken for classical reasons) · 🟢 Acceptable · 🔵 Post-quantum.

### Combined risk

`Risk = Category × Exposure × Reach` (0–16), in
[quantum_ready/riesgo.py](quantum_ready/riesgo.py).

| Category | Weight | | Factor | Weight |
|---|---|---|---|---|
| 🔴 Critical | 4 | | Exposure high / low | 2 / 1 |
| ⚪ Obsolete | 3 | | Reach high / low | 2 / 1 |
| 🟡 Warning | 2 | | | |
| 🟢 Acceptable | 1 | | | |
| 🔵 Post-quantum | 0 | | | |

Levels: 0 None · 1–3 Low · 4–7 Medium · 8–11 High · 12–16 Urgent.

### Output

- **JSON** (`informe.json`): `resumen` (summary), `servicios` (worst risk and
  count per category), `hallazgos` (findings: file, line, directive, value,
  algorithm, category, risk with its formula, recommendation and rationale),
  `avisos` (warnings: unevaluated defaults, OpenSSL aliases, referenced
  certificates…) and `no_reconocidos` (names with no rule, to review by hand).
- **Human-readable summary** on standard output, grouped by service and algorithm.

## Phase 2 — Hybrid key exchange

Simulation of an ML-KEM-768 + X25519 hybrid exchange between a Client and a
Server ([quantum_ready/tunel/](quantum_ready/tunel/)):

```bash
python -m quantum_ready.tunel            # -o to change the output JSON
```

Roles follow the X25519MLKEM768 (TLS 1.3) and mlkem768x25519-sha256 (OpenSSH)
standards:

1. The Client generates ML-KEM-768 and X25519 key pairs; the Server, an X25519 pair.
2. Client → Server (ClientHello): ML-KEM public key + X25519 public key (1216 B).
3. The Server encapsulates against the Client's ML-KEM public key (secret +
   ciphertext) and runs X25519 with the Client's public key.
   Server → Client (ServerHello): ciphertext + X25519 public key (1120 B).
4. The Client decapsulates the ciphertext and runs X25519 with the Server's
   public key.
5. Each side separately derives `HKDF-SHA384(ML-KEM_secret || X25519_secret)`
   → a 32-byte key, and both keys are checked to match. The order (ML-KEM
   first) is the one used by X25519MLKEM768 (TLS 1.3) and
   mlkem768x25519-sha256 (OpenSSH).
6. An Attacker with only the network data tries with its own private keys, by
   treating the public data as secrets, and by re-encapsulating; it never gets
   the key.

It prints every key and secret (actor, type, size and a hex excerpt), a size
table and ✅/❌ checks. Sizes are saved to `resultados_intercambio.json` for the
Phase 3 overhead analysis, together with the bytes on the wire in each
direction (`cliente_a_servidor` 1216, `servidor_a_cliente` 1120, total 2336)
and those of an X25519-only exchange (64). The program exits with code 1 if any
check fails.

## Phase 3 — Network impact

Measures the real cost (bytes and time) of three key exchanges over TCP on
localhost, with artificial latency to simulate different networks
([quantum_ready/red/](quantum_ready/red/)):

```bash
python -m quantum_ready.red                             # 100 repetitions, ~7 min
python -m quantum_ready.red -n 10 --perfiles fibra,4g   # quick run
```

- **Scenarios:** pure X25519, pure ML-KEM-768 and hybrid (the Phase 2 actors,
  with X25519MLKEM768 roles).
- **Profiles** (latency per leg, applied before each send; a handshake has two
  legs): Fibre 2 ms · 4G 50 ms · LEO satellite 25 ms · GEO satellite 600 ms.
- **Measured time:** from when the Client starts generating keys (with the TCP
  connection already open) until it holds the final key. The Server derives its
  key before replying, so at that point both sides have it.
- **Methodology:** the Server runs in a separate process (with threads, GIL
  contention added ~0.5 ms per handshake); scenarios are interleaved within
  each profile to spread any system drift, and 2 warm-up handshakes are
  discarded per combination (the first one in each process is 25–60 ms slower).

Output: a scenario × profile table (mean ± standard deviation and bytes), the
hybrid's overhead versus X25519 in bytes and time per profile, and
`resultados_overhead.json` with every run, the aggregates (mean, standard
deviation, median, min, max and time without the injected latency) and a
cross-check against the Phase 2 bytes when `resultados_intercambio.json` exists.

Latency is simulated without a bandwidth model: message size only affects time
through computation and the local TCP stack.

### Results on the reference machine

100 runs per cell; mean time of the full handshake.

| Scenario | Fibre (2 ms) | 4G (50 ms) | LEO (25 ms) | GEO (600 ms) | Bytes |
|---|---|---|---|---|---|
| X25519 | 4.84 ms | 100.96 ms | 50.88 ms | 1201.00 ms | 64 |
| ML-KEM-768 | 5.15 ms | 101.51 ms | 51.26 ms | 1201.63 ms | 2272 |
| Hybrid | 5.76 ms | 102.03 ms | 51.78 ms | 1202.11 ms | 2336 |

The hybrid costs about 1 ms more than X25519 in every profile: +19 % on fibre
but only +0.1 % on GEO satellite. In bytes it is +3550 % (+2272 B).

## Tests

```bash
.venv/Scripts/python -m pytest
```

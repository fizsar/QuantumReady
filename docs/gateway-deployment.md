# Deploying the hybrid TLS gateway (Phase 5)

[Español](gateway-despliegue.md) · **English** · [← Back to the README](../README.en.md)

Steps to bring up, from scratch on a clean machine, the gateway that only
accepts the X25519MLKEM768 hybrid key exchange, and to check it with
`openssl s_client`.

It is a **gateway demo**, not a product: it uses a self-signed certificate
(with a classical ECDSA P-256 signature) and a test backend that serves,
read-only, the findings of the Phase 1 scanner.

The tool's output, command-line options and file names are in Spanish; the
expected outputs below are shown as the tool prints them.

## Verified minimum requirements

| Component | Requirement | Version it was verified with |
|---|---|---|
| System | Linux; on Windows, WSL2 | Windows 10 (build 19045) with WSL 2.7.14 |
| Distribution | Ubuntu 26.04 LTS | Ubuntu 26.04.1 LTS |
| Python | 3.14 or later | 3.14.4 |
| OpenSSL used by Python's `ssl` module | **3.5 or later** (ML-KEM arrived in 3.5) | 3.5.5 |
| `openssl` command (verifier and self-test) | **3.5 or later** | 3.5.5 |
| Python packages | `cryptography` and `PyYAML` | 46.0.5 and 6.0.3 (Ubuntu packages) |
| Other | `git` | 2.53.0 |

Only that combination has been tested. Other Linux distributions or earlier
Python versions with OpenSSL 3.5 may work, but they have not been checked.
**The Windows Python does not work**: it ships OpenSSL 3.0 (see
[What happens if the requirements are not met](#what-happens-if-the-requirements-are-not-met)).

## 1. Install WSL2 with Ubuntu 26.04 (Windows only)

In PowerShell as administrator:

```powershell
wsl --install -d Ubuntu-26.04
```

Restart if asked, open "Ubuntu 26.04 LTS" from the Start menu and create your
Linux user. Check that it uses WSL 2:

```powershell
wsl -l -v
```

All remaining steps run **inside Ubuntu**.

## 2. Check the versions

```bash
python3 --version
python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
openssl version
openssl list -tls-groups -tls1_3 | tr ':' '\n' | grep -x X25519MLKEM768
python3 -c "import cryptography, yaml; print('dependencias ok')"
```

Expected output (from the verification run):

```
Python 3.14.4
OpenSSL 3.5.5 27 Jan 2026
OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)
X25519MLKEM768
dependencias ok
```

If the fourth command does not print `X25519MLKEM768`, the installed OpenSSL
does not support the hybrid group.

## 3. Install dependencies (if any is missing)

They come preinstalled on Ubuntu 26.04. If one is missing on your system:

```bash
sudo apt update
sudo apt install -y git openssl python3-cryptography python3-yaml
```

## 4. Clone the repository

Preferably on the Linux file system (`~`) rather than under `/mnt/c`: it is
faster and Unix permissions work.

```bash
cd ~
git clone https://github.com/fizsar/QuantumReady.git
cd QuantumReady
```

Nothing needs to be installed with pip: the gateway only uses the standard
library and the packages from step 3.

## 5. Generate the certificate

```bash
python3 -m quantum_ready.gateway.certificado
```

```
Certificado: ~/.quantum_ready/gateway/gateway-cert.pem
Clave:       ~/.quantum_ready/gateway/gateway-clave.pem
```

The private key is created with `600` permissions. The proxy also generates
the certificate if it does not exist, so this step is optional.

## 6. Start the backend (terminal 1)

```bash
python3 -m quantum_ready.gateway.backend_prueba
```

```
[backend] escuchando en http://127.0.0.1:8080 (sin TLS) · 84 hallazgos de escaneo de inventario.yaml al arrancar
```

A clean clone has no `informe.json`, so the backend runs the Phase 1 scanner
at startup.

## 7. Start the proxy (terminal 2)

```bash
python3 -m quantum_ready.gateway.proxy
```

Before opening port 8443, the proxy runs its security self-test:

```
[proxy] Autotest de seguridad:
  ✅ cliente híbrido X25519MLKEM768 (control positivo): ACEPTADO (TLSv1.3, X25519MLKEM768)
  ✅ cliente con grupos solo clásicos: rechazado (el servidor cerró la conexión sin completar el handshake)
  ✅ cliente que intenta bajar a TLS 1.2: rechazado (el servidor cerró la conexión sin completar el handshake)
[proxy] escuchando en https://127.0.0.1:8443 -> http://127.0.0.1:8080 (solo X25519MLKEM768, TLS 1.3)
LISTO
```

(The hybrid control client is accepted; the classical-only client and the
TLS 1.2 downgrade are rejected.) Two `[autotest] HANDSHAKE RECHAZADO …` lines
appear above: they are the two clients the self-test deliberately tries to
sneak in.

## 8. Verify with `openssl s_client` (terminal 3)

```bash
python3 -m quantum_ready.gateway.verificar --ruta /hallazgos
```

```
✅ Grupo negociado: X25519MLKEM768 (TLSv1.3)
✅ Respuesta del backend: HTTP/1.1 200 OK {"fuente": "escaneo de inventario.yaml al arrancar", "total": 84, …
✅ Cliente solo X25519 clásico: rechazado (el servidor cerró la conexión sin completar el handshake)

Resultado: extremo a extremo con X25519MLKEM768 ✅
```

The same check, directly with `openssl`:

```bash
openssl s_client -connect 127.0.0.1:8443 -groups X25519MLKEM768 \
  -CAfile ~/.quantum_ready/gateway/gateway-cert.pem </dev/null 2>/dev/null \
  | grep -E "Negotiated TLS1.3 group|Verify return code"
```

```
Negotiated TLS1.3 group: X25519MLKEM768
Verify return code: 0 (ok)
```

The line that proves the hybrid exchange is `Negotiated TLS1.3 group:
X25519MLKEM768`. A classical connection does not show that line but `Peer Temp
Key: X25519, 253 bits`. A client that only offers X25519 cannot connect:

```bash
openssl s_client -connect 127.0.0.1:8443 -groups X25519 </dev/null 2>&1 \
  | grep -E "Negotiated TLS1.3 group|^New,"
```

```
Negotiated TLS1.3 group: <NULL>
New, (NONE), Cipher is (NONE)
```

The proxy logs it (terminal 2):

```
[proxy] HANDSHAKE RECHAZADO 127.0.0.1:…: el cliente no ofrece X25519MLKEM768 (solo grupos clásicos) [NO_SUITABLE_KEY_SHARE]
```

### Optional: tests and load test

```bash
python3 -m quantum_ready.gateway.carga      # 30 simultaneous TLS clients
sudo apt update && sudo apt install -y python3-pytest
python3 -m pytest tests/test_gateway.py
```

`python3-pytest` is in Ubuntu's `universe` component: if `apt install` cannot
find it, the `apt update` is missing.

## What happens if the requirements are not met

The proxy **does not start** in an unsafe state: it stops with an explicit
error and exit code 1.

| Situation | Where it stops | Message | Checked? |
|---|---|---|---|
| Python's `ssl` uses OpenSSL < 3.5 (e.g. the Windows Python, with 3.0.15) | Version check, before the self-test | `El módulo ssl usa OpenSSL 3.0.15 3 Sep 2024; X25519MLKEM768 requiere OpenSSL 3.5 o posterior.` ("the ssl module uses OpenSSL 3.0.15; X25519MLKEM768 requires OpenSSL 3.5 or later") | Yes, with the Windows Python 3.13 |
| The `openssl` command is missing | Self-test | `No se encuentra el comando openssl, necesario para verificar el grupo negociado.` ("the openssl command, needed to verify the negotiated group, cannot be found") | Yes, on Ubuntu 26.04 without `openssl` in `PATH` |
| The `openssl` command is < 3.5 | Self-test: the positive control fails because the client cannot request the group | `openssl` 3.2.1 answers `group 'X25519MLKEM768' cannot be set` | `openssl` 3.2.1 message checked; the proxy stopping is derived from the self-test, not provoked |
| The configuration would accept classical groups | Self-test | `❌ cliente con grupos solo clásicos: ACEPTADO (…)` and `El gateway NO arranca: …` ("the gateway does NOT start: it would accept connections without hybrid key exchange or cannot verify it") | Yes, forcing `QR_GATEWAY_GRUPOS=X25519MLKEM768:X25519` |

## Stop and clean up

`Ctrl+C` in terminals 1 and 2. The gateway's certificate, key and OpenSSL
configuration live in `~/.quantum_ready/gateway`; to start from scratch:

```bash
rm -rf ~/.quantum_ready/gateway
```

If ports 8080 or 8443 are taken, change them with `backend_prueba --puerto`,
`proxy --puerto --backend 127.0.0.1:PORT` and `verificar --puerto`.

## How this document was verified

On 27 September 2026 the public repository was cloned (commit `c01526f`) with
an empty `HOME` on Ubuntu 26.04 (WSL2), and steps 2 and 4 to 8 were run
exactly as shown here; the outputs shown are the ones obtained. **Not run**:
step 1 (`wsl --install`, which installs the system) and the `apt install`
commands in step 3 and the optional section, which require administrator
rights; they are the official commands.

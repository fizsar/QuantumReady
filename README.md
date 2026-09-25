# Quantum Ready — Escáner de cripto-agilidad (Fase 1)

Detecta en archivos de configuración y certificados los algoritmos que romperá
(o debilitará) un ordenador cuántico, y los prioriza según la exposición y el
alcance de cada servicio.

## Uso

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
# .venv/bin/python -m pip install -r requirements.txt     # Linux/macOS

# Escanear todo lo que hay en el inventario
python -m quantum_ready -i ejemplos/inventario.yaml

# Escanear rutas concretas (se asocian a su servicio del inventario si lo hay)
python -m quantum_ready ejemplos/bastion ejemplos/vpn/wg0.conf -i ejemplos/inventario.yaml

# Opciones
#   -o informe.json          archivo JSON de salida ('-' = salida estándar)
#   --nivel-minimo Medio     detallar en el resumen desde este nivel (por defecto Alto)
```

Sin `-i`, se usa `./inventario.yaml` si existe. Los archivos que no pertenecen a
ningún servicio se escanean igual, pero su riesgo combinado queda **sin evaluar**:
el escáner no adivina exposición ni alcance.

## Formatos soportados

| Formato | Qué se analiza |
|---|---|
| `sshd_config` / `ssh_config` | KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms, PubkeyAccepted*, CASignatureAlgorithms, HostKey |
| nginx | ssl_protocols, ssl_ciphers, ssl_ecdh_curve, ssl_conf_command |
| Apache | SSLProtocol (resuelve `all -X`), SSLCipherSuite, SSLOpenSSLConfCmd |
| strongSwan (`ipsec.conf`, `swanctl.conf`) | ike/esp/proposals, authby/leftauth/rightauth |
| WireGuard (`wg*.conf`) | PresharedKey por `[Peer]` |
| Certificados (`.pem`, `.crt`, `.cer`, `.der`) | clave pública (tipo y tamaño) y firma (algoritmo y hash), cadenas con varios bloques |

El formato se detecta por nombre de archivo y, si no basta, por contenido.

## Libro de reglas

Todas las clasificaciones viven en [quantum_ready/reglas.py](quantum_ready/reglas.py):
`ALGORITMOS` (categoría, recomendación y motivo) y `PATRONES` (cómo se reconoce
cada nombre). Reglas destacadas:

- **Híbridos primero.** `mlkem768x25519-sha256`, `sntrup761x25519-sha512`,
  `X25519MLKEM768`… se comprueban antes que ningún substring y cortan la
  búsqueda, así no se marcan como 🔴 por contener `x25519`. En IPsec, una
  propuesta con ML-KEM y un intercambio clásico cuenta como híbrida.
- **Modo CBC.** Cualquier cifrado en CBC (explícito, o implícito en los nombres
  OpenSSL sin GCM/CCM como `ECDHE-RSA-AES128-SHA256`) pasa a ⚪ Obsoleto.
- **WireGuard.** Peer sin PresharedKey → 🔴 Crítico; con PresharedKey → 🟡
  Advertencia, con la explicación en el informe.

## Riesgo combinado

`Riesgo = Categoría × Exposición × Alcance` (0–16), en
[quantum_ready/riesgo.py](quantum_ready/riesgo.py).

| Categoría | Peso | | Factor | Peso |
|---|---|---|---|---|
| 🔴 Crítico | 4 | | Exposición alta / baja | 2 / 1 |
| ⚪ Obsoleto | 3 | | Alcance alto / bajo | 2 / 1 |
| 🟡 Advertencia | 2 | | | |
| 🟢 Aceptable | 1 | | | |
| 🔵 Post-cuántico | 0 | | | |

Niveles: 0 Ninguno · 1–3 Bajo · 4–7 Medio · 8–11 Alto · 12–16 Urgente.

## Salida

- **JSON** (`informe.json`): `resumen`, `servicios` (riesgo máximo y conteo por
  categoría), `hallazgos` (archivo, línea, directiva, valor, algoritmo, categoría,
  riesgo con su fórmula, recomendación y motivo), `avisos` (valores por defecto no
  evaluados, alias de OpenSSL, certificados referenciados…) y `no_reconocidos`
  (nombres sin regla en el libro, para revisar a mano).
- **Resumen legible** por la salida estándar, agrupado por servicio y algoritmo.

## Tests

```bash
.venv/Scripts/python -m pytest
```

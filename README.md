# Quantum Ready

**Español** · [English](README.en.md)

Herramientas para preparar una infraestructura para la criptografía
post-cuántica:

1. **Escáner de cripto-agilidad** — detecta en archivos de configuración y
   certificados los algoritmos que romperá (o debilitará) un ordenador cuántico,
   y los prioriza según la exposición y el alcance de cada servicio.
2. **Intercambio de claves híbrido** — simulación de ML-KEM-768 + X25519 con los
   papeles y el orden del estándar X25519MLKEM768 (TLS 1.3).
3. **Impacto en red** — mide sobre TCP real el coste en bytes y tiempo de
   X25519, ML-KEM-768 e híbrido con distintos perfiles de latencia.
4. **Informe ejecutivo** — PDF en castellano o inglés que traduce los
   resultados de las tres fases para directivos sin conocimientos de criptografía.

## Fase 1 — Escáner de cripto-agilidad

### Uso

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

### Formatos soportados

| Formato | Qué se analiza |
|---|---|
| `sshd_config` / `ssh_config` | KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms, PubkeyAccepted*, CASignatureAlgorithms, HostKey |
| nginx | ssl_protocols, ssl_ciphers, ssl_ecdh_curve, ssl_conf_command |
| Apache | SSLProtocol (resuelve `all -X`), SSLCipherSuite, SSLOpenSSLConfCmd |
| strongSwan (`ipsec.conf`, `swanctl.conf`) | ike/esp/proposals, authby/leftauth/rightauth |
| WireGuard (`wg*.conf`) | PresharedKey por `[Peer]` |
| Certificados (`.pem`, `.crt`, `.cer`, `.der`) | clave pública (tipo y tamaño) y firma (algoritmo y hash), cadenas con varios bloques |

El formato se detecta por nombre de archivo y, si no basta, por contenido.

### Libro de reglas

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

Categorías: 🔴 Crítico (roto por Shor) · 🟡 Advertencia (debilitado por Grover) ·
⚪ Obsoleto (roto por motivos clásicos) · 🟢 Aceptable · 🔵 Post-cuántico.

### Riesgo combinado

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

### Salida

- **JSON** (`informe.json`): `resumen`, `servicios` (riesgo máximo y conteo por
  categoría), `hallazgos` (archivo, línea, directiva, valor, algoritmo, categoría,
  riesgo con su fórmula, recomendación y motivo), `avisos` (valores por defecto no
  evaluados, alias de OpenSSL, certificados referenciados…) y `no_reconocidos`
  (nombres sin regla en el libro, para revisar a mano).
- **Resumen legible** por la salida estándar, agrupado por servicio y algoritmo.

## Fase 2 — Intercambio de claves híbrido

Simulación de un intercambio híbrido ML-KEM-768 + X25519 entre Cliente y Servidor
([quantum_ready/tunel/](quantum_ready/tunel/)):

```bash
python -m quantum_ready.tunel            # -o para cambiar el JSON de salida
```

Los papeles son los del estándar X25519MLKEM768 (TLS 1.3) y
mlkem768x25519-sha256 (OpenSSH):

1. El Cliente genera pares ML-KEM-768 y X25519; el Servidor, un par X25519.
2. Cliente → Servidor (ClientHello): pública ML-KEM + pública X25519 (1216 B).
3. El Servidor encapsula contra la pública ML-KEM del Cliente (secreto +
   ciphertext) y hace X25519 con la pública del Cliente.
   Servidor → Cliente (ServerHello): ciphertext + pública X25519 (1120 B).
4. El Cliente decapsula el ciphertext y hace X25519 con la pública del Servidor.
5. Cada parte deriva por separado `HKDF-SHA384(secreto_ML-KEM || secreto_X25519)`
   → clave de 32 bytes, y se comprueba que coinciden. El orden (ML-KEM primero)
   es el del estándar X25519MLKEM768 (TLS 1.3) y mlkem768x25519-sha256 (OpenSSH).
6. Un Atacante con solo los datos de red lo intenta con sus propias claves
   privadas, tratando los datos públicos como secretos y re-encapsulando; no
   obtiene la clave.

Muestra cada clave y secreto (actor, tipo, tamaño y extracto hexadecimal), una
tabla de tamaños y las comprobaciones ✅/❌. Los tamaños se guardan en
`resultados_intercambio.json` para el análisis de overhead de la Fase 3, junto
con los bytes en red en cada dirección (`cliente_a_servidor` 1216,
`servidor_a_cliente` 1120, total 2336) y los de un intercambio solo X25519 (64).
El programa termina con código 1 si alguna comprobación falla.

## Fase 3 — Impacto en red

Mide el coste real (bytes y tiempo) de tres intercambios de claves sobre TCP en
localhost, con latencia artificial para simular distintas redes
([quantum_ready/red/](quantum_ready/red/)):

```bash
python -m quantum_ready.red                       # 100 repeticiones, ~7 min
python -m quantum_ready.red -n 10 --perfiles fibra,4g   # prueba rápida
```

- **Escenarios:** X25519 puro, ML-KEM-768 puro e híbrido (los actores de la
  Fase 2, con los papeles de X25519MLKEM768).
- **Perfiles** (latencia por tramo, aplicada antes de cada envío; un handshake
  tiene dos tramos): Fibra 2 ms · 4G 50 ms · Satélite LEO 25 ms · Satélite GEO 600 ms.
- **Tiempo medido:** desde que el Cliente empieza a generar claves (con la
  conexión TCP ya abierta) hasta que tiene la clave final. El Servidor deriva la
  suya antes de responder, así que en ese momento ambas partes la tienen.
- **Metodología:** el Servidor corre en un proceso aparte (con hilos, la
  contención del GIL añadía ~0,5 ms por handshake); los escenarios se alternan
  dentro de cada perfil para repartir cualquier deriva del sistema, y se
  descartan 2 handshakes de calentamiento por combinación (el primero de cada
  proceso es 25-60 ms más lento).

Salida: tabla escenario × perfil (media ± desviación y bytes), overhead del
híbrido frente a X25519 en bytes y en tiempo por perfil, y
`resultados_overhead.json` con cada ejecución, los agregados (media, desviación,
mediana, mín., máx. y tiempo sin la latencia inyectada) y el contraste con los
bytes de la Fase 2 si existe `resultados_intercambio.json`.

La latencia se simula sin modelo de ancho de banda: el tamaño de los mensajes
solo influye en el tiempo a través del cómputo y de la pila TCP local.

### Resultados en el equipo de referencia

100 ejecuciones por celda; tiempo medio del handshake completo.

| Escenario | Fibra (2 ms) | 4G (50 ms) | LEO (25 ms) | GEO (600 ms) | Bytes |
|---|---|---|---|---|---|
| X25519 | 4,84 ms | 100,96 ms | 50,88 ms | 1201,00 ms | 64 |
| ML-KEM-768 | 5,15 ms | 101,51 ms | 51,26 ms | 1201,63 ms | 2272 |
| Híbrido | 5,76 ms | 102,03 ms | 51,78 ms | 1202,11 ms | 2336 |

El híbrido cuesta ~1 ms más que X25519 en todos los perfiles: +19 % en fibra,
pero solo +0,1 % en satélite GEO. En bytes es +3550 % (+2272 B).

## Fase 4 — Informe ejecutivo

Genera un PDF para dirección a partir de los resultados de las Fases 1-3
([quantum_ready/informe/](quantum_ready/informe/)):

```bash
python -m quantum_ready -i ejemplos/inventario.yaml     # Fase 1 → informe.json
python -m quantum_ready.tunel                           # Fase 2 → resultados_intercambio.json
python -m quantum_ready.informe --idioma es             # → informe_ejecutivo_es.pdf
python -m quantum_ready.informe --idioma en --empresa ejemplos/empresa.yaml
```

La Fase 3 se lee de `resultados_overhead.referencia.json`, la medición de
referencia incluida en el repositorio (para regenerarla:
`python -m quantum_ready.red -o resultados_overhead.referencia.json`). Las rutas
se cambian con `--fase1`, `--fase2` y `--fase3`. Los datos de la empresa salen
de `--empresa` (YAML), de `--empresa-nombre`, `--empresa-sector` y
`--empresa-contacto`, o de una empresa ficticia por defecto.

Secciones: portada, resumen ejecutivo, hallazgos por prioridad, la solución
propuesta, coste de la migración, qué queda pendiente y apéndice técnico. Cada
una es una entrada del índice del PDF.

- **Riesgo global por el peor caso:** algún Urgente → Crítico; si no, algún
  Alto → Alto; si no, algún Medio → Medio; si no, Bajo.
- **Qué resuelve la solución, sin exagerar:** los hallazgos prioritarios se
  reparten entre intercambio de claves (los resuelve el túnel híbrido), firmas
  (pendientes del ecosistema post-cuántico) y configuración (se corrigen hoy).
  RSA se clasifica según dónde aparece: en claves de host, certificados,
  `authby` o suites `ECDHE-RSA-…` es una firma; solo el transporte de claves
  RSA (`TLS_RSA_WITH_…`) es intercambio.
- **Coste contado con los datos:** la frase sobre el tiempo añadido se deriva
  de las mediciones ("menos de 1 ms en todos / en la mayoría de perfiles" solo
  si es cierto; si no, el valor aproximado y el rango).
- **Bilingüe:** todos los textos están en
  [traducciones.py](quantum_ready/informe/traducciones.py); los tests comprueban
  que ambos idiomas tienen las mismas claves y marcadores.

## Tests

```bash
.venv/Scripts/python -m pytest
```

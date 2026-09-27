# Despliegue del gateway TLS híbrido (Fase 5)

**Español** · [English](gateway-deployment.md) · [← Volver al README](../README.md)

Pasos para levantar desde cero, en una máquina limpia, el gateway que solo
acepta el intercambio de claves híbrido X25519MLKEM768 y comprobarlo con
`openssl s_client`.

Es una **demo de gateway**, no un producto: usa un certificado autofirmado
(con firma clásica ECDSA P-256) y un backend de prueba que sirve, en solo
lectura, los hallazgos del escáner de la Fase 1.

## Requisitos mínimos verificados

| Componente | Requisito | Versión con la que se ha verificado |
|---|---|---|
| Sistema | Linux; en Windows, WSL2 | Windows 10 (build 19045) con WSL 2.7.14 |
| Distribución | Ubuntu 26.04 LTS | Ubuntu 26.04.1 LTS |
| Python | 3.14 o posterior | 3.14.4 |
| OpenSSL del módulo `ssl` de Python | **3.5 o posterior** (ML-KEM llegó en la 3.5) | 3.5.5 |
| Comando `openssl` (verificador y autotest) | **3.5 o posterior** | 3.5.5 |
| Paquetes de Python | `cryptography` y `PyYAML` | 46.0.5 y 6.0.3 (paquetes de Ubuntu) |
| Otros | `git` | 2.53.0 |

Solo se ha probado esa combinación. Otras distribuciones Linux o versiones
anteriores de Python con OpenSSL 3.5 pueden funcionar, pero no están
comprobadas. **El Python de Windows no sirve**: usa OpenSSL 3.0 (ver
[Qué pasa si no se cumplen los requisitos](#qué-pasa-si-no-se-cumplen-los-requisitos)).

## 1. Instalar WSL2 con Ubuntu 26.04 (solo en Windows)

En PowerShell como administrador:

```powershell
wsl --install -d Ubuntu-26.04
```

Reinicia si lo pide, abre "Ubuntu 26.04 LTS" desde el menú Inicio y crea tu
usuario de Linux. Comprueba que usa WSL 2:

```powershell
wsl -l -v
```

El resto de pasos se ejecutan **dentro de Ubuntu**.

## 2. Comprobar las versiones

```bash
python3 --version
python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
openssl version
openssl list -tls-groups -tls1_3 | tr ':' '\n' | grep -x X25519MLKEM768
python3 -c "import cryptography, yaml; print('dependencias ok')"
```

Salida esperada (la de la verificación):

```
Python 3.14.4
OpenSSL 3.5.5 27 Jan 2026
OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)
X25519MLKEM768
dependencias ok
```

Si la cuarta orden no imprime `X25519MLKEM768`, el OpenSSL instalado no admite
el grupo híbrido.

## 3. Instalar dependencias (si falta alguna)

En Ubuntu 26.04 vienen de serie. Si en tu sistema falta alguna:

```bash
sudo apt update
sudo apt install -y git openssl python3-cryptography python3-yaml
```

## 4. Clonar el repositorio

Mejor en el sistema de archivos de Linux (`~`) que en `/mnt/c`: es más rápido y
los permisos de Unix funcionan.

```bash
cd ~
git clone https://github.com/fizsar/QuantumReady.git
cd QuantumReady
```

No hace falta instalar nada con pip: el gateway solo usa la biblioteca estándar
y los paquetes del paso 3.

## 5. Generar el certificado

```bash
python3 -m quantum_ready.gateway.certificado
```

```
Certificado: ~/.quantum_ready/gateway/gateway-cert.pem
Clave:       ~/.quantum_ready/gateway/gateway-clave.pem
```

La clave privada se crea con permisos `600`. El proxy también genera el
certificado si no existe, así que este paso es opcional.

## 6. Arrancar el backend (terminal 1)

```bash
python3 -m quantum_ready.gateway.backend_prueba
```

```
[backend] escuchando en http://127.0.0.1:8080 (sin TLS) · 84 hallazgos de escaneo de inventario.yaml al arrancar
```

En un clon limpio no existe `informe.json`, así que el backend ejecuta el
escáner de la Fase 1 al arrancar.

## 7. Arrancar el proxy (terminal 2)

```bash
python3 -m quantum_ready.gateway.proxy
```

Antes de abrir el puerto 8443, el proxy ejecuta su autotest de seguridad:

```
[proxy] Autotest de seguridad:
  ✅ cliente híbrido X25519MLKEM768 (control positivo): ACEPTADO (TLSv1.3, X25519MLKEM768)
  ✅ cliente con grupos solo clásicos: rechazado (el servidor cerró la conexión sin completar el handshake)
  ✅ cliente que intenta bajar a TLS 1.2: rechazado (el servidor cerró la conexión sin completar el handshake)
[proxy] escuchando en https://127.0.0.1:8443 -> http://127.0.0.1:8080 (solo X25519MLKEM768, TLS 1.3)
LISTO
```

Encima aparecen dos líneas `[autotest] HANDSHAKE RECHAZADO …`: son los dos
clientes que el autotest intenta colar a propósito.

## 8. Verificar con `openssl s_client` (terminal 3)

```bash
python3 -m quantum_ready.gateway.verificar --ruta /hallazgos
```

```
✅ Grupo negociado: X25519MLKEM768 (TLSv1.3)
✅ Respuesta del backend: HTTP/1.1 200 OK {"fuente": "escaneo de inventario.yaml al arrancar", "total": 84, …
✅ Cliente solo X25519 clásico: rechazado (el servidor cerró la conexión sin completar el handshake)

Resultado: extremo a extremo con X25519MLKEM768 ✅
```

La misma comprobación, directamente con `openssl`:

```bash
openssl s_client -connect 127.0.0.1:8443 -groups X25519MLKEM768 \
  -CAfile ~/.quantum_ready/gateway/gateway-cert.pem </dev/null 2>/dev/null \
  | grep -E "Negotiated TLS1.3 group|Verify return code"
```

```
Negotiated TLS1.3 group: X25519MLKEM768
Verify return code: 0 (ok)
```

La línea que prueba el intercambio híbrido es `Negotiated TLS1.3 group:
X25519MLKEM768`. En una conexión clásica no aparece esa línea, sino `Peer Temp
Key: X25519, 253 bits`. Un cliente que solo ofrece X25519 no llega a conectar:

```bash
openssl s_client -connect 127.0.0.1:8443 -groups X25519 </dev/null 2>&1 \
  | grep -E "Negotiated TLS1.3 group|^New,"
```

```
Negotiated TLS1.3 group: <NULL>
New, (NONE), Cipher is (NONE)
```

El proxy lo registra en su log (terminal 2):

```
[proxy] HANDSHAKE RECHAZADO 127.0.0.1:…: el cliente no ofrece X25519MLKEM768 (solo grupos clásicos) [NO_SUITABLE_KEY_SHARE]
```

### Opcional: tests y prueba de carga

```bash
python3 -m quantum_ready.gateway.carga      # 30 clientes TLS simultáneos
sudo apt update && sudo apt install -y python3-pytest
python3 -m pytest tests/test_gateway.py
```

`python3-pytest` está en el componente `universe` de Ubuntu: si `apt install`
no lo encuentra, es que falta el `apt update`.

## Qué pasa si no se cumplen los requisitos

El proxy **no arranca** en un estado inseguro: se detiene con un error
explícito y el código de salida 1.

| Situación | Dónde se detiene | Mensaje | ¿Comprobado? |
|---|---|---|---|
| El `ssl` de Python usa OpenSSL < 3.5 (p. ej. el Python de Windows, con 3.0.15) | Comprobación de versión, antes del autotest | `El módulo ssl usa OpenSSL 3.0.15 3 Sep 2024; X25519MLKEM768 requiere OpenSSL 3.5 o posterior.` | Sí, con el Python 3.13 de Windows |
| No está el comando `openssl` | Autotest | `No se encuentra el comando openssl, necesario para verificar el grupo negociado.` | Sí, en Ubuntu 26.04 sin `openssl` en el `PATH` |
| El comando `openssl` es < 3.5 | Autotest: falla el control positivo porque el cliente no puede pedir el grupo | `openssl` 3.2.1 responde `group 'X25519MLKEM768' cannot be set` | Mensaje de `openssl` 3.2.1 comprobado; la parada del proxy se deduce del autotest, no se ha provocado |
| La configuración aceptaría grupos clásicos | Autotest | `❌ cliente con grupos solo clásicos: ACEPTADO (…)` y `El gateway NO arranca: aceptaría conexiones sin intercambio híbrido o no puede verificarlo.` | Sí, forzando `QR_GATEWAY_GRUPOS=X25519MLKEM768:X25519` |

## Parar y limpiar

`Ctrl+C` en las terminales 1 y 2. El certificado, la clave y la configuración
de OpenSSL del gateway están en `~/.quantum_ready/gateway`; para empezar de
cero:

```bash
rm -rf ~/.quantum_ready/gateway
```

Si los puertos 8080 u 8443 están ocupados, se pueden cambiar con
`backend_prueba --puerto`, `proxy --puerto --backend 127.0.0.1:PUERTO` y
`verificar --puerto`.

## Cómo se ha verificado este documento

El 27 de septiembre de 2026 se clonó el repositorio público (commit `c01526f`)
con un `HOME` vacío en Ubuntu 26.04 (WSL2) y se ejecutaron los pasos 2 y 4 a 8
tal como aparecen aquí; las salidas mostradas son las obtenidas. **No se
ejecutaron**: el paso 1 (`wsl --install`, que instala el sistema) ni los
`apt install` de los pasos 3 y opcional, que requieren permisos de
administrador; son los comandos oficiales.

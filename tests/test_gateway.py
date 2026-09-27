"""Tests del gateway (Fase 5).

Los unitarios se ejecutan en cualquier sistema. Los de integración arrancan el
backend y el proxy de verdad y solo se ejecutan en Linux con OpenSSL >= 3.5
(p. ej. Ubuntu 26.04 en WSL2); en Windows y en CI con OpenSSL 3.0 se saltan.
"""

import ast
import json
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from quantum_ready.gateway import conf_openssl
from quantum_ready.gateway.backend_prueba import RESPUESTA
from quantum_ready.gateway.reenvio import forzar_cierre, longitud_cuerpo
from quantum_ready.gateway.s_client import ResultadoSClient
from quantum_ready.gateway.verificar import json_de

RAIZ = Path(__file__).parent.parent
GATEWAY = RAIZ / "quantum_ready" / "gateway"

# --- Salidas reales de openssl s_client 3.5.5 (recortadas) -----------------------------
SALIDA_HIBRIDA = """\
Connecting to 127.0.0.1
CONNECTED(00000003)
Negotiated TLS1.3 group: X25519MLKEM768
SSL handshake has read 2394 bytes and written 1528 bytes
Verification: OK
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
"""
SALIDA_CLASICA = """\
CONNECTED(00000003)
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
"""
SALIDA_RECHAZO_ALERTA = """\
4057305657720000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:../ssl/record/rec_layer_s3.c:918:SSL alert number 40
CONNECTED(00000003)
Negotiated TLS1.3 group: <NULL>
New, (NONE), Cipher is (NONE)
"""
SALIDA_RECHAZO_CIERRE = """\
40F7236A05790000:error:0A000126:SSL routines::unexpected eof while reading:../ssl/record/rec_layer_s3.c:698:
CONNECTED(00000003)
Negotiated TLS1.3 group: <NULL>
SSL handshake has read 0 bytes and written 306 bytes
New, (NONE), Cipher is (NONE)
"""
SALIDA_FALLO_LOCAL = """\
40C76814D0790000:error:0A0000B5:SSL routines:ssl_cipher_list_to_bytes:no ciphers available:../ssl/statem/statem_clnt.c:4184:No ciphers enabled for max supported SSL/TLS version
CONNECTED(00000003)
SSL handshake has read 0 bytes and written 7 bytes
New, (NONE), Cipher is (NONE)
"""


def test_s_client_hibrido():
    r = ResultadoSClient(SALIDA_HIBRIDA)
    assert r.conectado and r.version == "TLSv1.3"
    assert r.grupo_negociado == "X25519MLKEM768"
    assert r.cifrado == "TLS_AES_256_GCM_SHA384"
    assert r.clave_temporal is None


def test_s_client_clasico_no_tiene_linea_de_grupo():
    """Una conexión clásica se reconoce por "Peer Temp Key", no por "Negotiated"."""
    r = ResultadoSClient(SALIDA_CLASICA)
    assert r.conectado
    assert r.grupo_negociado is None
    assert r.clave_temporal == "X25519, 253 bits"
    assert "clave temporal clásica X25519" in r.describir()


@pytest.mark.parametrize("salida, motivo", [
    (SALIDA_RECHAZO_ALERTA, "alerta TLS 40"),
    (SALIDA_RECHAZO_CIERRE, "cerró la conexión"),
])
def test_s_client_rechazo_del_servidor(salida, motivo):
    r = ResultadoSClient(salida)
    assert not r.conectado and r.rechazado_por_el_servidor
    assert r.grupo_negociado is None  # "<NULL>"
    assert motivo in r.describir()


def test_s_client_fallo_local_no_cuenta_como_rechazo():
    r = ResultadoSClient(SALIDA_FALLO_LOCAL)
    assert not r.conectado and not r.rechazado_por_el_servidor
    assert "no ciphers available" in r.describir()


# --- Configuración de OpenSSL ------------------------------------------------------------
def _escribir(ruta: Path, texto: str) -> Path:
    ruta.write_text(texto, encoding="utf-8")
    return ruta


def test_conf_como_la_de_ubuntu_amplia_su_seccion_de_inicio(tmp_path):
    sistema = _escribir(tmp_path / "openssl.cnf", (
        "openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n"
        "[provider_sect]\ndefault = default_sect\n[default_sect]\nactivate = 1\n"))
    texto = conf_openssl.contenido(sistema)
    assert f".include {sistema}" in texto
    assert "openssl_conf =" not in texto  # se reutiliza el openssl_init del sistema
    assert "[openssl_init]\nssl_conf = qr_gateway_ssl" in texto
    assert "[qr_gateway_tls]\nGroups = X25519MLKEM768" in texto


def test_conf_con_cadena_completa_solo_anade_groups(tmp_path):
    sistema = _escribir(tmp_path / "openssl.cnf", (
        "openssl_conf = ini\n[ini]\nssl_conf = s\n[s]\nsystem_default = tls\n"
        "[tls]\nCipherString = DEFAULT:@SECLEVEL=2\n"))
    texto = conf_openssl.contenido(sistema)
    assert texto.rstrip().endswith("[tls]\nGroups = X25519MLKEM768")
    assert "ssl_conf" not in texto and "system_default" not in texto  # no se pisan


def test_conf_sigue_los_include_de_carpetas(tmp_path):
    carpeta = tmp_path / "conf.d"
    carpeta.mkdir()
    _escribir(carpeta / "10-tls.cnf", "[ini]\nssl_conf = s\n[s]\nsystem_default = tls\n")
    sistema = _escribir(tmp_path / "openssl.cnf",
                        f"openssl_conf = ini\n[ini]\nproviders = p\n.include {carpeta}\n")
    assert conf_openssl.contenido(sistema).rstrip().endswith("[tls]\nGroups = X25519MLKEM768")


def test_conf_sin_configuracion_del_sistema(tmp_path):
    texto = conf_openssl.contenido(tmp_path / "no_existe.cnf")
    lineas = [ln for ln in texto.splitlines() if ln and not ln.startswith("#")]
    assert lineas[0] == "openssl_conf = qr_gateway_init"
    assert ".include" not in texto
    assert "Groups = X25519MLKEM768" in texto


def test_conf_grupos_configurables(tmp_path):
    assert "Groups = A:B" in conf_openssl.contenido(None, "A:B")


# --- El orden de los imports del proxy -------------------------------------------------
_CARGAN_OPENSSL = {"ssl", "_ssl", "asyncio", "hashlib", "_hashlib", "http", "urllib",
                   "quantum_ready.gateway.certificado", "quantum_ready.gateway.s_client",
                   "quantum_ready.gateway.reenvio"}


def _modulos(nodo: ast.stmt) -> list[str]:
    if isinstance(nodo, ast.Import):
        return [a.name for a in nodo.names]
    if isinstance(nodo, ast.ImportFrom):
        return [f"{nodo.module}.{a.name}" for a in nodo.names] + [nodo.module or ""]
    return []


def test_proxy_fija_openssl_conf_antes_de_cargar_openssl():
    arbol = ast.parse((GATEWAY / "proxy.py").read_text(encoding="utf-8"))
    fija = next(i for i, n in enumerate(arbol.body)
                if isinstance(n, ast.Assign) and "OPENSSL_CONF" in ast.unparse(n.targets[0]))
    antes = [m for n in arbol.body[:fija] for m in _modulos(n)]
    despues = [m for n in arbol.body[fija:] for m in _modulos(n)]
    assert not [m for m in antes if m.split(".")[0] in _CARGAN_OPENSSL or m in _CARGAN_OPENSSL]
    assert "ssl" in despues and "asyncio" in despues


@pytest.mark.parametrize("modulo", ["conf_openssl.py", "__init__.py"])
def test_modulos_previos_no_importan_openssl(modulo):
    arbol = ast.parse((GATEWAY / modulo).read_text(encoding="utf-8"))
    permitidos = {"__future__", "os", "re", "subprocess", "pathlib"}
    importados = {m.split(".")[0] for n in ast.walk(arbol) for m in _modulos(n) if m}
    assert importados <= permitidos


# --- Reenvío HTTP --------------------------------------------------------------------------
def test_forzar_cierre():
    cabecera = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"
    assert forzar_cierre(cabecera) == b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    assert forzar_cierre(b"GET / HTTP/1.1\r\n\r\n").endswith(b"Connection: close\r\n\r\n")


def test_longitud_cuerpo():
    assert longitud_cuerpo(b"POST / HTTP/1.1\r\nContent-Length: 12\r\n\r\n") == 12
    assert longitud_cuerpo(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == 0


def test_json_de_corta_por_content_length():
    cuerpo = json.dumps(RESPUESTA)
    respuesta = (f"HTTP/1.0 200 OK\r\nContent-Length: {len(cuerpo)}\r\n\r\n{cuerpo}"
                 "---\nPost-Handshake New Session Ticket arrived:\n 0000 - ..}..\n")
    assert json_de(respuesta) == RESPUESTA


# --- Integración: backend + proxy reales ----------------------------------------------------
def _openssl_35() -> bool:
    if sys.platform != "linux" or not shutil.which("openssl"):
        return False
    import ssl
    version = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout
    cli = tuple(int(x) for x in re.search(r"(\d+)\.(\d+)", version).groups())
    return ssl.OPENSSL_VERSION_INFO >= (3, 5) and cli >= (3, 5)


integracion = pytest.mark.skipif(not _openssl_35(),
                                 reason="requiere Linux con OpenSSL >= 3.5 (p. ej. Ubuntu 26.04)")


def _puerto_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _lanzar(modulo: str, *args: str, env: dict) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-m", modulo, *args], cwd=RAIZ, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _esperar_listo(proceso: subprocess.Popen, tiempo: float = 30) -> str:
    """Lee la salida hasta "LISTO" o hasta que el proceso termine."""
    salida, limite = [], time.monotonic() + tiempo
    while time.monotonic() < limite:
        linea = proceso.stdout.readline()
        if not linea and proceso.poll() is not None:
            break
        salida.append(linea)
        if linea.strip() == "LISTO":
            break
    return "".join(salida)


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    """Arranca backend y proxy; devuelve una función para lanzar más proxies."""
    import os
    monkeypatch.setenv("QR_GATEWAY_DIR", str(tmp_path))
    base_env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    procesos = []
    puerto_backend = _puerto_libre()
    procesos.append(_lanzar("quantum_ready.gateway.backend_prueba", "--puerto",
                            str(puerto_backend), env=base_env))

    def arrancar_proxy(**extra_env):
        puerto = _puerto_libre()
        proceso = _lanzar("quantum_ready.gateway.proxy", "--puerto", str(puerto),
                          "--backend", f"127.0.0.1:{puerto_backend}",
                          env={**base_env, **extra_env})
        procesos.append(proceso)
        return puerto, proceso, _esperar_listo(proceso)

    time.sleep(0.5)  # el backend arranca en milisegundos
    yield arrancar_proxy
    for p in procesos:
        p.terminate()
        p.wait(timeout=10)


@integracion
def test_extremo_a_extremo_con_x25519mlkem768(gateway):
    from quantum_ready.gateway.verificar import verificar
    puerto, _, arranque = gateway()
    assert "LISTO" in arranque, arranque
    assert "grupos solo clásicos: rechazado" in arranque
    assert "bajar a TLS 1.2: rechazado" in arranque
    ok, lineas = verificar("127.0.0.1", puerto)
    assert ok, "\n".join(lineas)
    assert "Grupo negociado: X25519MLKEM768" in lineas[0]
    assert json.dumps(RESPUESTA) in lineas[1]


@integracion
@pytest.mark.parametrize("opciones", [("-groups", "X25519"),
                                      ("-groups", "X25519:secp256r1:secp384r1"),
                                      ("-tls1_2",)])
def test_rechaza_clientes_clasicos(gateway, opciones):
    from quantum_ready.gateway.s_client import ejecutar
    puerto, _, _ = gateway()
    r = ejecutar("127.0.0.1", puerto, *opciones)
    assert r.rechazado_por_el_servidor, r.describir()


@integracion
def test_se_niega_a_arrancar_si_acepta_grupos_clasicos(gateway):
    """Si la configuración admitiera X25519, el autotest lo detecta y no arranca."""
    _, proceso, salida = gateway(QR_GATEWAY_GRUPOS="X25519MLKEM768:X25519")
    assert proceso.wait(timeout=30) == 1
    assert "LISTO" not in salida
    assert "grupos solo clásicos: ACEPTADO" in salida
    assert "NO arranca" in salida


@integracion
def test_incluye_la_configuracion_del_sistema(gateway, tmp_path):
    """Un ajuste de la configuración 'del sistema' (Ciphersuites) se conserva."""
    from quantum_ready.gateway.s_client import ejecutar
    sistema = _escribir(tmp_path / "sistema.cnf", (
        "openssl_conf = ini\n[ini]\nssl_conf = s\n[s]\nsystem_default = tls\n"
        "[tls]\nCiphersuites = TLS_CHACHA20_POLY1305_SHA256\n"))
    puerto, _, arranque = gateway(OPENSSL_CONF=str(sistema))
    assert "LISTO" in arranque, arranque
    r = ejecutar("127.0.0.1", puerto, "-groups", "X25519MLKEM768")
    assert r.grupo_negociado == "X25519MLKEM768"
    assert r.cifrado == "TLS_CHACHA20_POLY1305_SHA256"

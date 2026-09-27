"""Tests del gateway (Fase 5).

Los unitarios se ejecutan en cualquier sistema. Los de integración arrancan el
backend y el proxy de verdad y solo se ejecutan en Linux con OpenSSL >= 3.5
(p. ej. Ubuntu 26.04 en WSL2); en Windows y en CI con OpenSSL 3.0 se saltan.
"""

import ast
import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from quantum_ready.gateway import conf_openssl
from quantum_ready.gateway.backend_prueba import RESPUESTA, TAMANO_GRANDE, Backend
from quantum_ready.gateway.reenvio import (ErrorHTTP, Limites, forzar_cierre,
                                           leer_peticion, longitud_cuerpo,
                                           prefijo_valido, reenviar, respuesta_error,
                                           validar_cabecera)
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


# --- Robustez del reenvío, sin TLS (cualquier sistema, también CI) ----------------------
@pytest.mark.parametrize("datos, valido", [
    (b"", True),
    (b"GE", True),
    (b"GET /ruta HT", True),
    (b"GET / HTTP/1.1\r\nHost: x", True),
    (b"get / HTTP/1.1", False),          # método en minúsculas
    (b" / HTTP/1.1", False),             # sin método
    (b"GET / FTP/1.0\r\n", False),      # línea completa pero no HTTP
    (b"\x16\x03\x01\x02\x00", False),     # un ClientHello TLS no es HTTP
    (os.urandom(64) + b"\x00", False),   # bytes aleatorios
], ids=["vacio", "metodo-a-medias", "linea-a-medias", "cabecera-a-medias", "minusculas",
        "sin-metodo", "no-http", "clienthello-tls", "aleatorio"])
def test_prefijo_valido(datos, valido):
    assert prefijo_valido(datos) is valido


@pytest.mark.parametrize("cabecera, codigo", [
    (b"GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n", 400),
    (b"GET / HTTP/1.1\r\nsin dos puntos\r\n\r\n", 400),
    (b"GET / HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n", 413),
])
def test_validar_cabecera_rechaza(cabecera, codigo):
    with pytest.raises(ErrorHTTP) as e:
        validar_cabecera(cabecera, Limites())
    assert e.value.codigo == codigo


def test_respuesta_error_es_http_valido():
    r = respuesta_error(502, "backend no disponible")
    cabecera, cuerpo = r.split(b"\r\n\r\n", 1)
    assert cabecera.startswith(b"HTTP/1.1 502 Bad Gateway")
    assert f"Content-Length: {len(cuerpo)}".encode() in cabecera
    assert json.loads(cuerpo) == {"error": "Bad Gateway", "detalle": "backend no disponible"}


def _leer(datos: bytes, eof: bool = True, timeout: float = 5):
    async def principal():
        lector = asyncio.StreamReader()
        lector.feed_data(datos)
        if eof:
            lector.feed_eof()
        return await leer_peticion(lector, Limites(timeout_s=timeout))
    return asyncio.run(principal())


def test_leer_peticion_con_cuerpo():
    cabecera, cuerpo = _leer(b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nholaEXTRA")
    assert cabecera.startswith(b"POST /x") and cuerpo == b"holaE"  # 5 bytes


@pytest.mark.parametrize("datos, eof, codigo", [
    (os.urandom(512) + b"\x00", True, 400),                  # basura: 400 al momento
    (b"GET /" + b"a" * 70_000, True, 431),                    # cabecera enorme
    (b"GET / HTTP/1.1\r\nHost: x", False, 408),              # nunca termina
], ids=["basura-400", "cabecera-enorme-431", "incompleta-408"])
def test_leer_peticion_errores(datos, eof, codigo):
    with pytest.raises(ErrorHTTP) as e:
        _leer(datos, eof=eof, timeout=0.1)
    assert e.value.codigo == codigo


def test_leer_peticion_cliente_cierra_antes_de_terminar():
    with pytest.raises(ConnectionResetError):
        _leer(b"GET / HTTP/1.1\r\n")


async def _pila(limites: Limites, backend_activo: bool = True):
    """Backend de prueba + reenvío, en el mismo bucle y sin TLS."""
    backend = Backend()
    srv_backend = await asyncio.start_server(backend.atender, "127.0.0.1", 0)
    puerto_backend = srv_backend.sockets[0].getsockname()[1]
    if not backend_activo:  # puerto que existió y ya no escucha: backend caído
        srv_backend.close()
        await srv_backend.wait_closed()
    srv_proxy = await asyncio.start_server(
        lambda r, w: reenviar(r, w, ("127.0.0.1", puerto_backend), limites), "127.0.0.1", 0)
    return backend, srv_backend, srv_proxy, srv_proxy.sockets[0].getsockname()[1]


async def _get(puerto: int, datos: bytes) -> bytes:
    lector, escritor = await asyncio.open_connection("127.0.0.1", puerto)
    escritor.write(datos)
    await escritor.drain()
    respuesta = await lector.read()
    escritor.close()
    return respuesta


def _peticion(ruta: str) -> bytes:
    return f"GET {ruta} HTTP/1.1\r\nHost: x\r\n\r\n".encode()


def _codigo(respuesta: bytes) -> int:
    return int(respuesta.split(b" ", 2)[1])


def test_backend_caido_da_502():
    async def principal():
        _, _, proxy, puerto = await _pila(Limites(), backend_activo=False)
        async with proxy:
            return await _get(puerto, _peticion("/"))
    respuesta = asyncio.run(principal())
    assert _codigo(respuesta) == 502
    assert b"backend no disponible" in respuesta


def test_backend_lento_da_504():
    async def principal():
        _, backend, proxy, puerto = await _pila(Limites(timeout_s=0.1))
        async with backend, proxy:
            return await _get(puerto, _peticion("/lento"))
    assert _codigo(asyncio.run(principal())) == 504


def test_basura_da_400_sin_esperar():
    async def principal():
        _, backend, proxy, puerto = await _pila(Limites(timeout_s=5))
        async with backend, proxy:
            return await asyncio.wait_for(_get(puerto, os.urandom(512) + b"\x00"), 1)
    assert _codigo(asyncio.run(principal())) == 400


def test_cliente_que_corta_no_deja_conexiones_con_el_backend():
    async def principal():
        estado, backend, proxy, puerto = await _pila(Limites())
        async with backend, proxy:
            lector, escritor = await asyncio.open_connection("127.0.0.1", puerto)
            escritor.write(_peticion("/grande"))
            await lector.readexactly(100_000)
            escritor.transport.abort()  # corte brusco a mitad de la respuesta
            for _ in range(50):
                await asyncio.sleep(0.05)
                if estado.conexiones_abiertas == 0:
                    break
            despues = await _get(puerto, _peticion("/"))
            return estado.conexiones_abiertas, despues
    abiertas, despues = asyncio.run(principal())
    assert abiertas == 0
    assert _codigo(despues) == 200


def test_peticiones_lentas_no_bloquean_a_las_demas():
    async def principal():
        _, backend, proxy, puerto = await _pila(Limites())
        async with backend, proxy:
            inicio = asyncio.get_running_loop().time()
            respuestas = await asyncio.gather(*(_get(puerto, _peticion("/lento" if i % 2 else "/"))
                                                for i in range(20)))
            return asyncio.get_running_loop().time() - inicio, respuestas
    total, respuestas = asyncio.run(principal())
    assert all(_codigo(r) == 200 for r in respuestas)
    assert total < 2  # en secuencia serían al menos 10 x 0,5 s = 5 s


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


class Pila:
    """Backend y proxies reales lanzados como procesos."""

    def __init__(self, base_env: dict):
        self.base_env = base_env
        self.procesos: list[subprocess.Popen] = []
        self.puerto_backend = _puerto_libre()
        self.backend = _lanzar("quantum_ready.gateway.backend_prueba", "--puerto",
                               str(self.puerto_backend), env=base_env)
        self.procesos.append(self.backend)
        time.sleep(0.5)  # el backend arranca en milisegundos

    def arrancar_proxy(self, *opciones: str, **extra_env):
        puerto = _puerto_libre()
        proceso = _lanzar("quantum_ready.gateway.proxy", "--puerto", str(puerto),
                          "--backend", f"127.0.0.1:{self.puerto_backend}", *opciones,
                          env={**self.base_env, **extra_env})
        self.procesos.append(proceso)
        return puerto, proceso, _esperar_listo(proceso)

    def detener_backend(self) -> None:
        self.backend.terminate()
        self.backend.wait(timeout=10)

    def cerrar(self) -> None:
        for p in self.procesos:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=10)


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    monkeypatch.setenv("QR_GATEWAY_DIR", str(tmp_path))
    pila = Pila({k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"})
    yield pila
    pila.cerrar()


def _tls(puerto: int):
    import ssl
    from quantum_ready.gateway.carga import contexto_cliente
    s = socket.create_connection(("127.0.0.1", puerto), timeout=30)
    return contexto_cliente().wrap_socket(s, server_hostname="localhost")


def _recibir_todo(s) -> bytes:
    datos = b""
    while trozo := s.recv(65536):
        datos += trozo
    return datos


@integracion
def test_extremo_a_extremo_con_x25519mlkem768(gateway):
    from quantum_ready.gateway.verificar import verificar
    puerto, _, arranque = gateway.arrancar_proxy()
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
    puerto, _, _ = gateway.arrancar_proxy()
    r = ejecutar("127.0.0.1", puerto, *opciones)
    assert r.rechazado_por_el_servidor, r.describir()


@integracion
def test_se_niega_a_arrancar_si_acepta_grupos_clasicos(gateway):
    """Si la configuración admitiera X25519, el autotest lo detecta y no arranca."""
    _, proceso, salida = gateway.arrancar_proxy(QR_GATEWAY_GRUPOS="X25519MLKEM768:X25519")
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
    puerto, _, arranque = gateway.arrancar_proxy(OPENSSL_CONF=str(sistema))
    assert "LISTO" in arranque, arranque
    r = ejecutar("127.0.0.1", puerto, "-groups", "X25519MLKEM768")
    assert r.grupo_negociado == "X25519MLKEM768"
    assert r.cifrado == "TLS_CHACHA20_POLY1305_SHA256"


@integracion
def test_carga_30_clientes_tls_concurrentes(gateway):
    from quantum_ready.gateway.carga import concurrente
    puerto, _, arranque = gateway.arrancar_proxy()
    assert "LISTO" in arranque, arranque
    total, resultados = asyncio.run(concurrente("127.0.0.1", puerto, 30))
    assert all(r.estado == 200 for r in resultados), [r.error for r in resultados]
    assert total < 2.5  # en secuencia serían al menos 15 x 0,5 s = 7,5 s


@integracion
def test_tls_backend_apagado_da_502(gateway):
    puerto, _, _ = gateway.arrancar_proxy()
    gateway.detener_backend()
    with _tls(puerto) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        respuesta = _recibir_todo(s)
    assert respuesta.startswith(b"HTTP/1.1 502 Bad Gateway")


@integracion
def test_tls_cliente_corta_a_mitad(gateway):
    import urllib.request
    puerto, proceso, _ = gateway.arrancar_proxy()
    with _tls(puerto) as s:
        s.sendall(b"GET /grande HTTP/1.1\r\nHost: x\r\n\r\n")
        recibidos = 0
        while recibidos < 100_000:
            recibidos += len(s.recv(65536))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01" + b"\x00" * 7)  # RST
    url = f"http://127.0.0.1:{gateway.puerto_backend}/estado"
    for _ in range(50):
        time.sleep(0.1)
        with urllib.request.urlopen(url) as r:
            abiertas = json.load(r)["conexiones_abiertas"]
        if abiertas == 0:
            break
    assert recibidos < TAMANO_GRANDE and abiertas == 0
    assert proceso.poll() is None
    with _tls(puerto) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert _recibir_todo(s).startswith(b"HTTP/1.1 200")


@integracion
def test_tls_peticion_malformada(gateway):
    puerto, proceso, _ = gateway.arrancar_proxy()
    inicio = time.monotonic()
    with _tls(puerto) as s:
        s.sendall(os.urandom(512) + b"\x00")
        respuesta = _recibir_todo(s)
    assert respuesta.startswith(b"HTTP/1.1 400 Bad Request")
    assert time.monotonic() - inicio < 2  # no espera al timeout de 10 s
    with socket.create_connection(("127.0.0.1", puerto), timeout=5) as s:
        s.sendall(os.urandom(512))  # ni siquiera es TLS
        try:
            _recibir_todo(s)  # el proxy cierra la conexión
        except ConnectionResetError:
            pass
    assert proceso.poll() is None


@integracion
def test_tls_timeouts_de_cliente(gateway):
    puerto, _, _ = gateway.arrancar_proxy("--timeout", "1")
    with _tls(puerto) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: x")  # cabecera sin terminar
        assert _recibir_todo(s).startswith(b"HTTP/1.1 408 Request Timeout")
    inicio = time.monotonic()
    with socket.create_connection(("127.0.0.1", puerto), timeout=30) as s:
        _recibir_todo(s)  # TCP abierto sin handshake: el proxy lo cierra
    assert time.monotonic() - inicio < 5



# --- Registro de los handshakes rechazados -------------------------------------------------
from quantum_ready.gateway import handshake  # noqa: E402


def _error_ssl(reason: str):
    import ssl
    e = ssl.SSLError(1, "fallo simulado")
    e.reason = reason
    return e


@pytest.mark.parametrize("error, texto", [
    (lambda: _error_ssl("NO_SUITABLE_KEY_SHARE"), "no ofrece X25519MLKEM768"),
    (lambda: _error_ssl("UNSUPPORTED_PROTOCOL"), "se exige TLS 1.3"),
    (lambda: _error_ssl("RECORD_LAYER_FAILURE"), "no es TLS válido"),
    (lambda: _error_ssl("HTTP_REQUEST"), "HTTP en claro"),
    (lambda: _error_ssl("CODIGO_NUEVO"), "error TLS [CODIGO_NUEVO]"),
    (lambda: ConnectionAbortedError("SSL handshake is taking longer than 1.0 seconds"),
     "no se completó a tiempo"),
    (lambda: TimeoutError(), "no se completó a tiempo"),
    (lambda: ConnectionResetError(), "cerró la conexión durante el handshake"),
], ids=["clasico", "tls12", "basura", "http", "desconocido", "abortado", "timeout", "reset"])
def test_describir_rechazo(error, texto):
    assert texto in handshake.describir_rechazo(error())


def test_filtro_solo_quita_el_aviso_de_eof():
    import logging
    def registro(mensaje):
        return logging.LogRecord("asyncio", logging.WARNING, "", 0, mensaje, None, None)
    filtro = handshake._SinAvisoEofSsl()
    assert not filtro.filter(registro("returning true from eof_received() has no effect when using ssl"))
    assert filtro.filter(registro("otro aviso de asyncio"))


def test_handshake_rechazado_queda_registrado(tmp_path, capsys):
    """Con TLS clásico (vale en cualquier OpenSSL): TLS 1.2 y basura se registran."""
    import ssl
    from quantum_ready.gateway import certificado
    cert, clave = certificado.asegurar(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, clave)
    cliente_12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cliente_12.check_hostname, cliente_12.verify_mode = False, ssl.CERT_NONE
    cliente_12.maximum_version = ssl.TLSVersion.TLSv1_2

    async def principal():
        atendidas = []

        async def manejador(lector, escritor):
            atendidas.append(escritor.get_extra_info("ssl_object").version())
            escritor.close()

        srv = await handshake.servidor(ctx, "127.0.0.1", 0, 5, manejador)
        puerto = srv.sockets[0].getsockname()[1]
        async with srv:
            with pytest.raises((ssl.SSLError, ConnectionError)):
                await asyncio.open_connection("127.0.0.1", puerto, ssl=cliente_12)
            _, escritor = await asyncio.open_connection("127.0.0.1", puerto)
            escritor.write(os.urandom(300))
            await escritor.drain()
            await asyncio.sleep(0.5)
            escritor.close()
        return atendidas

    assert asyncio.run(principal()) == []  # ninguna llegó al manejador
    log = capsys.readouterr().out
    assert log.count("HANDSHAKE RECHAZADO") == 2
    assert "(se exige TLS 1.3) [UNSUPPORTED_PROTOCOL]" in log
    assert "no es TLS válido" in log  # RECORD_LAYER_FAILURE o WRONG_VERSION_NUMBER


@integracion
def test_tls_rechazos_quedan_en_el_log_del_proxy(gateway):
    from quantum_ready.gateway.s_client import ejecutar
    puerto, proceso, _ = gateway.arrancar_proxy()
    ejecutar("127.0.0.1", puerto, "-groups", "X25519")
    ejecutar("127.0.0.1", puerto, "-tls1_2")
    for datos in (os.urandom(300), b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"):
        with socket.create_connection(("127.0.0.1", puerto), timeout=5) as s:
            s.sendall(datos)
            try:
                s.recv(10)
            except ConnectionResetError:
                pass
    time.sleep(0.5)
    proceso.terminate()
    log = proceso.communicate(timeout=10)[0]
    rechazos = [ln for ln in log.splitlines() if ln.startswith("[proxy] HANDSHAKE RECHAZADO")]
    assert len(rechazos) == 4, log
    assert "[NO_SUITABLE_KEY_SHARE]" in rechazos[0]
    assert "[UNSUPPORTED_PROTOCOL]" in rechazos[1]
    assert "no es TLS válido" in rechazos[2]
    assert "[HTTP_REQUEST]" in rechazos[3]

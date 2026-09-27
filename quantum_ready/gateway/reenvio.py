"""Reenvío HTTP del gateway al backend: una petición por conexión.

Robustez operativa (no afecta a la negociación TLS híbrida):

- La petición se valida mientras llega: unos bytes que no empiezan como una
  línea de petición HTTP se rechazan con 400 al momento, sin esperar más datos.
- Timeouts: la petición completa del cliente (408), la conexión y cada lectura
  del backend (504) y cada escritura hacia el cliente.
- Backend caído -> 502. La respuesta se reenvía por trozos y la conexión con el
  backend se cierra siempre, también si el cliente corta a mitad.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from contextlib import suppress
from dataclasses import dataclass

GRUPO_HIBRIDO = "X25519MLKEM768"
TROZO = 64 * 1024

_LINEA_PETICION = re.compile(rb"([A-Z]{1,16}) (\S{1,8192}) HTTP/1\.[01]")
_METODO_PARCIAL = re.compile(rb"[A-Z]{0,16}")
_RAZONES = {400: "Bad Request", 408: "Request Timeout", 413: "Content Too Large",
            431: "Request Header Fields Too Large", 502: "Bad Gateway",
            504: "Gateway Timeout"}


@dataclass(frozen=True)
class Limites:
    timeout_s: float = 10.0
    max_cabecera: int = 64 * 1024
    max_cuerpo: int = 10 * 1024 * 1024


class ErrorHTTP(Exception):
    def __init__(self, codigo: int, detalle: str):
        super().__init__(detalle)
        self.codigo, self.detalle = codigo, detalle


# --- Validación de la petición -------------------------------------------------------
def prefijo_valido(datos: bytes) -> bool:
    """¿Puede ``datos`` ser el principio de una petición HTTP/1.x?"""
    primera = datos.split(b"\r\n", 1)[0]
    if not all(0x20 <= b < 0x7F for b in primera):
        return False
    metodo, espacio, _ = primera.partition(b" ")
    if not _METODO_PARCIAL.fullmatch(metodo) or (espacio and not metodo):
        return False
    return b"\r\n" not in datos or _LINEA_PETICION.fullmatch(primera) is not None


def longitud_cuerpo(cabecera: bytes) -> int:
    for linea in cabecera.split(b"\r\n")[1:]:
        nombre, _, valor = linea.partition(b":")
        if nombre.strip().lower() == b"content-length":
            valor = valor.strip()
            if not valor.isdigit():
                raise ErrorHTTP(400, "Content-Length no válido")
            return int(valor)
    return 0


def validar_cabecera(cabecera: bytes, limites: Limites) -> int:
    """Comprueba la cabecera completa y devuelve la longitud del cuerpo."""
    lineas = cabecera.rstrip(b"\r\n").split(b"\r\n")
    if not _LINEA_PETICION.fullmatch(lineas[0]):
        raise ErrorHTTP(400, "línea de petición HTTP no válida")
    if any(b":" not in linea for linea in lineas[1:]):
        raise ErrorHTTP(400, "cabecera HTTP no válida")
    longitud = longitud_cuerpo(cabecera)
    if longitud > limites.max_cuerpo:
        raise ErrorHTTP(413, f"cuerpo de {longitud} bytes (máximo {limites.max_cuerpo})")
    return longitud


async def leer_peticion(lector: asyncio.StreamReader, limites: Limites) -> tuple[bytes, bytes]:
    """(cabecera, cuerpo). ErrorHTTP si no es válida o no llega a tiempo."""
    datos = b""
    try:
        async with asyncio.timeout(limites.timeout_s):
            while b"\r\n\r\n" not in datos:
                if not prefijo_valido(datos):
                    raise ErrorHTTP(400, "los datos recibidos no son una petición HTTP")
                if len(datos) > limites.max_cabecera:
                    raise ErrorHTTP(431, f"cabecera de más de {limites.max_cabecera} bytes")
                trozo = await lector.read(4096)
                if not trozo:
                    raise ConnectionResetError("el cliente cerró antes de completar la petición")
                datos += trozo
            fin = datos.index(b"\r\n\r\n") + 4
            cabecera, resto = datos[:fin], datos[fin:]
            longitud = validar_cabecera(cabecera, limites)
            cuerpo = resto[:longitud]
            if len(cuerpo) < longitud:
                cuerpo += await lector.readexactly(longitud - len(cuerpo))
    except TimeoutError:
        raise ErrorHTTP(408, f"la petición no llegó completa en {limites.timeout_s:g} s") from None
    return cabecera, cuerpo


def forzar_cierre(cabecera: bytes) -> bytes:
    """Cabecera de la petición con ``Connection: close`` (una petición por conexión)."""
    lineas = cabecera.rstrip(b"\r\n").split(b"\r\n")
    lineas = [ln for ln in lineas if not ln.lower().startswith(b"connection:")]
    return b"\r\n".join(lineas + [b"Connection: close"]) + b"\r\n\r\n"


def respuesta_error(codigo: int, detalle: str) -> bytes:
    cuerpo = json.dumps({"error": _RAZONES[codigo], "detalle": detalle},
                        ensure_ascii=False).encode("utf-8")
    return (f"HTTP/1.1 {codigo} {_RAZONES[codigo]}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(cuerpo)}\r\nConnection: close\r\n\r\n").encode() + cuerpo


# --- Reenvío ----------------------------------------------------------------------------
async def _escribir(escritor: asyncio.StreamWriter, datos: bytes, limites: Limites) -> None:
    escritor.write(datos)
    await asyncio.wait_for(escritor.drain(), limites.timeout_s)


async def _hacia_el_backend(escritor: asyncio.StreamWriter, cabecera: bytes, cuerpo: bytes,
                            backend: tuple[str, int], limites: Limites) -> tuple[str, int]:
    """Pasa la petición al backend y copia su respuesta. Devuelve (estado, bytes)."""
    try:
        b_lector, b_escritor = await asyncio.wait_for(
            asyncio.open_connection(*backend), limites.timeout_s)
    except TimeoutError:
        raise ErrorHTTP(504, f"el backend no aceptó la conexión en {limites.timeout_s:g} s") from None
    except OSError as e:
        raise ErrorHTTP(502, f"backend no disponible ({e.strerror or type(e).__name__})") from None
    try:
        b_escritor.write(forzar_cierre(cabecera) + cuerpo)
        try:
            await asyncio.wait_for(b_escritor.drain(), limites.timeout_s)
            primero = await asyncio.wait_for(b_lector.read(TROZO), limites.timeout_s)
        except TimeoutError:
            raise ErrorHTTP(504, f"el backend no respondió en {limites.timeout_s:g} s") from None
        except OSError as e:
            raise ErrorHTTP(502, f"error al hablar con el backend ({type(e).__name__})") from None
        if not primero:
            raise ErrorHTTP(502, "el backend cerró la conexión sin responder")
        # A partir de aquí ya se ha empezado a responder: un fallo solo puede cerrar
        estado = primero.split(b"\r\n", 1)[0].decode("latin-1")
        await _escribir(escritor, primero, limites)
        enviados = len(primero)
        while trozo := await asyncio.wait_for(b_lector.read(TROZO), limites.timeout_s):
            await _escribir(escritor, trozo, limites)
            enviados += len(trozo)
        return estado, enviados
    finally:
        b_escritor.close()  # la conexión con el backend nunca queda abierta
        with suppress(Exception):
            await asyncio.wait_for(b_escritor.wait_closed(), 1)


async def reenviar(lector: asyncio.StreamReader, escritor: asyncio.StreamWriter,
                   backend: tuple[str, int], limites: Limites = Limites()) -> None:
    """Atiende una conexión: lee la petición, la reenvía y devuelve la respuesta."""
    ssl_obj = escritor.get_extra_info("ssl_object")
    origen = escritor.get_extra_info("peername") or ("?", 0)
    inicio = time.perf_counter()
    peticion, resultado = "-", ""
    try:
        try:
            cabecera, cuerpo = await leer_peticion(lector, limites)
            peticion = cabecera.split(b"\r\n", 1)[0].decode("latin-1")
            estado, enviados = await _hacia_el_backend(escritor, cabecera, cuerpo, backend,
                                                       limites)
            resultado = f"{estado} ({enviados} B)"
        except ErrorHTTP as e:
            await _escribir(escritor, respuesta_error(e.codigo, e.detalle), limites)
            resultado = f"{e.codigo} {_RAZONES[e.codigo]}: {e.detalle}"
    except (ConnectionError, TimeoutError, asyncio.IncompleteReadError) as e:
        resultado = f"conexión con el cliente interrumpida ({type(e).__name__})"
    except Exception as e:  # un fallo inesperado cierra esta conexión, no el proxy
        resultado = f"error inesperado ({type(e).__name__}: {e})"
    finally:
        escritor.close()
    ms = (time.perf_counter() - inicio) * 1000
    tls = f"{ssl_obj.version()} {ssl_obj.cipher()[0]}" if ssl_obj else "sin TLS"
    # Python 3.14 no puede leer el grupo negociado de la conexión: el que se
    # muestra es el único que admite la configuración (comprobado por el
    # autotest al arrancar), no uno verificado en esta conexión concreta.
    # La verificación por conexión se hace desde fuera con verificar.py.
    print(f"[proxy] {origen[0]}:{origen[1]} {tls} grupo={GRUPO_HIBRIDO} (forzado por "
          f"configuración, no verificado en esta conexión) | {peticion} -> {resultado} "
          f"[{ms:.0f} ms]", flush=True)

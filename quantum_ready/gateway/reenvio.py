"""Reenvío HTTP mínimo del gateway al backend: una petición por conexión."""

from __future__ import annotations

import asyncio

GRUPO_HIBRIDO = "X25519MLKEM768"


def forzar_cierre(cabecera: bytes) -> bytes:
    """Cabecera de la petición con ``Connection: close`` (una petición por conexión)."""
    lineas = cabecera.rstrip(b"\r\n").split(b"\r\n")
    lineas = [ln for ln in lineas if not ln.lower().startswith(b"connection:")]
    return b"\r\n".join(lineas + [b"Connection: close"]) + b"\r\n\r\n"


def longitud_cuerpo(cabecera: bytes) -> int:
    for linea in cabecera.split(b"\r\n")[1:]:
        nombre, _, valor = linea.partition(b":")
        if nombre.strip().lower() == b"content-length":
            return int(valor.strip())
    return 0


async def reenviar(lector: asyncio.StreamReader, escritor: asyncio.StreamWriter,
                   backend: tuple[str, int]) -> None:
    """Lee una petición del cliente, la pasa al backend y devuelve su respuesta tal cual."""
    ssl_obj = escritor.get_extra_info("ssl_object")
    origen = escritor.get_extra_info("peername")
    try:
        cabecera = await lector.readuntil(b"\r\n\r\n")
        cuerpo = await lector.readexactly(longitud_cuerpo(cabecera))
        b_lector, b_escritor = await asyncio.open_connection(*backend)
        b_escritor.write(forzar_cierre(cabecera) + cuerpo)
        await b_escritor.drain()
        respuesta = await b_lector.read()  # el backend cierra al terminar
        b_escritor.close()
        escritor.write(respuesta)
        await escritor.drain()
        peticion = cabecera.split(b"\r\n", 1)[0].decode("latin-1")
        estado = respuesta.split(b"\r\n", 1)[0].decode("latin-1")
        # Python 3.14 no puede leer el grupo negociado de la conexión: el que se
        # muestra es el único que admite la configuración (comprobado por el
        # autotest al arrancar), no uno verificado en esta conexión concreta.
        # La verificación por conexión se hace desde fuera con verificar.py.
        print(f"[proxy] {origen[0]}:{origen[1]} {ssl_obj.version()} "
              f"{ssl_obj.cipher()[0]} grupo={GRUPO_HIBRIDO} (forzado por configuración, "
              f"no verificado en esta conexión) | {peticion} -> {estado}", flush=True)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError,
            ValueError) as e:
        print(f"[proxy] {origen}: petición descartada ({type(e).__name__})", flush=True)
    finally:
        escritor.close()

"""Handshake TLS con registro de los rechazos.

Con ``asyncio.start_server(ssl=ctx)`` asyncio hace el handshake por su cuenta
y descarta en silencio las conexiones que fallan: el gateway no vería a los
clientes que rechaza su propia política. Aquí el servidor acepta TCP y hace el
handshake dentro del manejador con ``StreamWriter.start_tls`` y el MISMO
contexto TLS, así que cada rechazo queda registrado con su motivo.

Python 3.14 no puede leer el grupo negociado en una conexión que funciona,
pero cuando el handshake falla, ``ssl.SSLError.reason`` trae el código de
OpenSSL, que permite distinguir el motivo.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Awaitable, Callable

# Código de OpenSSL -> explicación.
MOTIVOS = {
    # Comprobados con clientes reales contra OpenSSL 3.5.5
    "NO_SUITABLE_KEY_SHARE": "el cliente no ofrece X25519MLKEM768 (solo grupos clásicos)",
    "UNSUPPORTED_PROTOCOL": "versión de TLS no admitida (se exige TLS 1.3)",
    "RECORD_LAYER_FAILURE": "lo recibido no es TLS válido",
    "HTTP_REQUEST": "petición HTTP en claro a un puerto TLS",
    # Bytes que no son TLS con OpenSSL 3.0.15 (comprobado en Windows)
    "WRONG_VERSION_NUMBER": "lo recibido no es TLS válido",
    # Posibles con otros clientes u otras versiones de OpenSSL (no comprobados)
    "NO_SHARED_GROUPS": "el cliente no ofrece X25519MLKEM768 (solo grupos clásicos)",
    "NO_SHARED_CIPHER": "ningún cifrado en común con el cliente",
}


class _SinAvisoEofSsl(logging.Filter):
    """Filtra un aviso inofensivo de asyncio al hacer start_tls en el servidor.

    Si el cliente cierra justo al terminar el handshake, asyncio puede recibir
    el EOF antes de marcar el flujo como TLS y avisa "returning true from
    eof_received() has no effect when using ssl". No afecta a la seguridad ni a
    la conexión, pero ensuciaría el registro de seguridad del gateway.
    """

    def filter(self, registro: logging.LogRecord) -> bool:
        return "eof_received() has no effect when using ssl" not in registro.getMessage()


_FILTRO_EOF = _SinAvisoEofSsl()

Manejador = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


def describir_rechazo(error: BaseException) -> str:
    """Explicación del fallo de handshake, con el código de OpenSSL si lo hay."""
    if isinstance(error, ssl.SSLError) and error.reason:
        return f"{MOTIVOS.get(error.reason, 'error TLS')} [{error.reason}]"
    # asyncio aborta un handshake lento con ConnectionAbortedError("... longer than ...")
    if isinstance(error, TimeoutError) or "longer than" in str(error):
        return "el handshake no se completó a tiempo"
    if isinstance(error, (ConnectionError, asyncio.IncompleteReadError, EOFError)):
        return f"el cliente cerró la conexión durante el handshake ({type(error).__name__})"
    return f"{type(error).__name__}: {error}"


async def atender(lector: asyncio.StreamReader, escritor: asyncio.StreamWriter,
                  ctx: ssl.SSLContext, timeout_s: float, manejador: Manejador,
                  etiqueta: str = "proxy") -> None:
    """Hace el handshake TLS; si falla lo registra, y si no pasa la conexión al manejador."""
    origen = escritor.get_extra_info("peername") or ("?", 0)
    try:
        await escritor.start_tls(ctx, ssl_handshake_timeout=timeout_s,
                                 ssl_shutdown_timeout=timeout_s)
    except (OSError, EOFError, asyncio.IncompleteReadError) as e:
        print(f"[{etiqueta}] HANDSHAKE RECHAZADO {origen[0]}:{origen[1]}: "
              f"{describir_rechazo(e)}", flush=True)
        escritor.transport.abort()
        return
    await manejador(lector, escritor)


async def servidor(ctx: ssl.SSLContext, host: str, puerto: int, timeout_s: float,
                   manejador: Manejador, etiqueta: str = "proxy") -> asyncio.Server:
    """Servidor TCP cuyas conexiones pasan por ``atender`` (handshake registrado)."""
    logging.getLogger("asyncio").addFilter(_FILTRO_EOF)  # idempotente
    return await asyncio.start_server(
        lambda r, w: atender(r, w, ctx, timeout_s, manejador, etiqueta), host, puerto)

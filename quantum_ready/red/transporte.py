"""Mensajes sobre TCP con latencia inyectada.

Cada mensaje viaja como ``longitud (4 bytes, big-endian) || datos``. La
latencia se aplica en el lado que envía, justo antes de escribir en el socket,
así que cada tramo del handshake la paga una vez.
"""

from __future__ import annotations

import socket
import struct
import time

CABECERA = struct.Struct("!I")
TAMANO_MAXIMO = 64 * 1024
# Por debajo de este margen se espera activamente: time.sleep puede pasarse
# de largo en algún milisegundo y el perfil de fibra es de solo 2 ms.
_MARGEN_ESPERA_ACTIVA = 0.002


def esperar(segundos: float) -> None:
    """Espera precisa: sleep para el grueso y espera activa para el final."""
    if segundos <= 0:
        return
    fin = time.perf_counter() + segundos
    if segundos > _MARGEN_ESPERA_ACTIVA:
        time.sleep(segundos - _MARGEN_ESPERA_ACTIVA)
    while time.perf_counter() < fin:
        pass


def configurar(sock: socket.socket) -> None:
    # Sin Nagle: cada mensaje sale en cuanto se escribe
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def enviar(sock: socket.socket, datos: bytes, latencia_s: float) -> int:
    """Espera la latencia del tramo y envía. Devuelve los bytes de carga útil."""
    if len(datos) > TAMANO_MAXIMO:
        raise ValueError(f"Mensaje demasiado grande: {len(datos)} bytes")
    esperar(latencia_s)
    sock.sendall(CABECERA.pack(len(datos)) + datos)
    return len(datos)


def recibir(sock: socket.socket) -> bytes:
    (longitud,) = CABECERA.unpack(_leer_exactamente(sock, CABECERA.size))
    if longitud > TAMANO_MAXIMO:
        raise ValueError(f"Longitud de mensaje no válida: {longitud}")
    return _leer_exactamente(sock, longitud)


def _leer_exactamente(sock: socket.socket, n: int) -> bytes:
    datos = bytearray()
    while len(datos) < n:
        trozo = sock.recv(n - len(datos))
        if not trozo:
            raise ConnectionError(f"Conexión cerrada tras {len(datos)} de {n} bytes")
        datos += trozo
    return bytes(datos)

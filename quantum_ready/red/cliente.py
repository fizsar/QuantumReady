"""Cliente TCP: ejecuta un handshake contra un ServidorHandshake."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from .escenarios import Escenario
from .transporte import configurar, enviar, recibir


@dataclass(frozen=True)
class ResultadoCliente:
    clave: bytes
    t_inicio: float  # perf_counter() justo antes de que el Cliente genere claves
    t_clave: float   # perf_counter() cuando el Cliente tiene la clave final
                     # (el Servidor ya la tenía: la deriva antes de responder)
    bytes_enviados: int
    bytes_recibidos: int


def ejecutar_handshake(direccion: tuple[str, int], escenario: Escenario,
                       latencia_s: float) -> ResultadoCliente:
    """Un handshake completo: Cliente → Servidor → Cliente.

    El cronómetro arranca con la conexión TCP ya abierta: se mide el
    intercambio de claves, no el handshake TCP (que en localhost es inmediato
    y no lleva latencia inyectada).
    """
    with socket.create_connection(direccion) as sock:
        configurar(sock)
        t_inicio = time.perf_counter()
        estado, mensaje = escenario.iniciar()
        enviado = enviar(sock, mensaje, latencia_s)
        respuesta = recibir(sock)
        clave = escenario.finalizar(estado, respuesta)
        t_clave = time.perf_counter()
    return ResultadoCliente(clave, t_inicio, t_clave, enviado, len(respuesta))

"""Servidor TCP en localhost, en su propio proceso, que atiende handshakes.

Va en un proceso aparte (no en un hilo) para que Cliente y Servidor no compitan
por el GIL de Python: con hilos, esa contención añadía ~0,5 ms por handshake
y se confundía con el coste criptográfico que se quiere medir.
"""

from __future__ import annotations

import multiprocessing as mp
import queue
import socket
from dataclasses import dataclass

from .escenarios import ESCENARIOS
from .transporte import configurar, enviar, recibir


@dataclass(frozen=True)
class ResultadoServidor:
    clave: bytes
    bytes_recibidos: int
    bytes_enviados: int


def _servir(escenario_id: str, latencia_s: float, resultados: mp.Queue,
            parar: mp.Event) -> None:
    """Bucle del proceso servidor: un handshake por conexión."""
    escenario = ESCENARIOS[escenario_id]
    with socket.create_server(("127.0.0.1", 0)) as escucha:
        escucha.settimeout(0.2)  # para poder comprobar si hay que parar
        resultados.put(escucha.getsockname()[:2])
        while not parar.is_set():
            try:
                conexion, _ = escucha.accept()
            except socket.timeout:
                continue
            with conexion:
                try:
                    configurar(conexion)
                    mensaje = recibir(conexion)
                    # La clave existe antes de enviar la respuesta: el Servidor
                    # siempre la tiene antes que el Cliente.
                    respuesta, clave = escenario.responder(mensaje)
                    enviado = enviar(conexion, respuesta, latencia_s)
                    resultados.put(ResultadoServidor(clave, len(mensaje), enviado))
                except Exception as e:  # se relanza en el proceso que mide
                    resultados.put(RuntimeError(f"Servidor {escenario_id}: {e!r}"))


class ServidorHandshake:
    """Arranca el proceso servidor y recoge lo que obtiene en cada handshake.

    Uso::

        with ServidorHandshake("hibrido", latencia_s) as servidor:
            ... conectar a servidor.direccion ...
            resultado = servidor.siguiente_resultado()
    """

    def __init__(self, escenario_id: str, latencia_s: float):
        if escenario_id not in ESCENARIOS:
            raise ValueError(f"Escenario desconocido: {escenario_id}")
        contexto = mp.get_context("spawn")  # igual en Windows, Linux y macOS
        self._resultados = contexto.Queue()
        self._parar = contexto.Event()
        self._proceso = contexto.Process(
            target=_servir, args=(escenario_id, latencia_s, self._resultados, self._parar),
            daemon=True, name=f"servidor-{escenario_id}")
        self.direccion: tuple[str, int] | None = None

    def __enter__(self) -> "ServidorHandshake":
        self._proceso.start()
        while self.direccion is None:
            try:
                self.direccion = tuple(self._resultados.get(timeout=0.5))
            except queue.Empty:
                if not self._proceso.is_alive():
                    raise RuntimeError("El proceso servidor terminó al arrancar "
                                       f"(código {self._proceso.exitcode})") from None
        return self

    def __exit__(self, *exc) -> None:
        self._parar.set()
        self._proceso.join(timeout=5)
        if self._proceso.is_alive():
            self._proceso.terminate()
            self._proceso.join()

    def siguiente_resultado(self, timeout: float = 30) -> ResultadoServidor:
        try:
            resultado = self._resultados.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("El servidor no ha respondido") from None
        if isinstance(resultado, BaseException):
            raise resultado
        return resultado

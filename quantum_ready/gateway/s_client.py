"""``openssl s_client`` como verificador externo del grupo negociado.

Python 3.14 no puede decir qué grupo de claves se negoció (``SSLSocket.group()``
llega en 3.15), así que se le pregunta a OpenSSL desde fuera. En su salida:

- ``Negotiated TLS1.3 group: X25519MLKEM768`` -> intercambio híbrido.
- ``Peer Temp Key: X25519, 253 bits`` -> intercambio clásico. En ese caso NO
  aparece la línea anterior: buscar solo "Negotiated..." haría que una
  conexión clásica pareciera "sin grupo" en lugar de clásica.
- ``New, (NONE)`` -> no hubo conexión. Fue el servidor quien la rechazó si
  además aparece ``SSL alert number N`` (envió una alerta TLS) o
  ``unexpected eof while reading`` (cerró la conexión tras recibir la
  propuesta del cliente: es lo que hace el servidor TLS de asyncio, que no
  llega a enviar la alerta). Un error local del cliente (p. ej.
  ``no ciphers available``) NO cuenta como rechazo del servidor.

El cliente se lanza SIN ``OPENSSL_CONF``: debe ofrecer lo que ofrecería un
cliente cualquiera, no heredar la restricción del gateway.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
from dataclasses import dataclass

TIEMPO_MAXIMO_S = 15


@dataclass(frozen=True)
class ResultadoSClient:
    salida: str

    def _buscar(self, patron: str) -> str | None:
        m = re.search(patron, self.salida, re.MULTILINE)
        return m.group(1) if m else None

    @property
    def conectado(self) -> bool:
        return self.version is not None

    @property
    def version(self) -> str | None:
        return self._buscar(r"^New, (TLSv[\d.]+)")

    @property
    def cifrado(self) -> str | None:
        return self._buscar(r"^New, TLSv[\d.]+, Cipher is (\S+)")

    @property
    def grupo_negociado(self) -> str | None:
        """Grupo TLS 1.3 negociado, o None ("<NULL>" = no se negoció ninguno)."""
        grupo = self._buscar(r"^Negotiated TLS1\.3 group: (\S+)")
        return None if grupo in (None, "<NULL>") else grupo

    @property
    def clave_temporal(self) -> str | None:
        """Clave efímera clásica ("X25519, 253 bits"), si la hubo."""
        return self._buscar(r"^(?:Peer|Server) Temp Key: ([^\n]+)")

    @property
    def alerta(self) -> int | None:
        """Número de alerta TLS recibida del otro extremo (40 = handshake failure)."""
        valor = self._buscar(r"SSL alert number (\d+)")
        return int(valor) if valor else None

    @property
    def cerrado_por_el_servidor(self) -> bool:
        return "unexpected eof while reading" in self.salida

    @property
    def rechazado_por_el_servidor(self) -> bool:
        return not self.conectado and (self.alerta is not None or self.cerrado_por_el_servidor)

    @property
    def motivo_rechazo(self) -> str:
        if self.alerta is not None:
            return f"alerta TLS {self.alerta}"
        if self.cerrado_por_el_servidor:
            return "el servidor cerró la conexión sin completar el handshake"
        return "sin rechazo del servidor"

    def describir(self) -> str:
        """Estado en una frase: conectado, rechazado por el servidor o fallo local."""
        if self.conectado:
            grupo = self.grupo_negociado or f"clave temporal clásica {self.clave_temporal}"
            return f"ACEPTADO ({self.version}, {grupo})"
        if self.rechazado_por_el_servidor:
            return f"rechazado ({self.motivo_rechazo})"
        error = re.search(r"error:[0-9A-F]+:[^:]*:[^:]*:([^:\n]+)", self.salida)
        return f"fallo del propio cliente, no del servidor ({error.group(1) if error else 'desconocido'})"

    @property
    def respuesta_http(self) -> str | None:
        """Respuesta HTTP recibida por la conexión, desde la línea de estado."""
        inicio = self.salida.find("HTTP/1.")
        return self.salida[inicio:] if inicio >= 0 else None


def comando(host: str, puerto: int, *opciones: str) -> list[str]:
    return ["openssl", "s_client", "-connect", f"{host}:{puerto}", *opciones]


def entorno_sin_restriccion() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}


def ejecutar(host: str, puerto: int, *opciones: str, entrada: bytes = b"") -> ResultadoSClient:
    proceso = subprocess.run(comando(host, puerto, *opciones), input=entrada,
                             capture_output=True, timeout=TIEMPO_MAXIMO_S,
                             env=entorno_sin_restriccion())
    return ResultadoSClient((proceso.stdout + proceso.stderr).decode("utf-8", "replace"))


async def ejecutar_async(host: str, puerto: int, *opciones: str) -> ResultadoSClient:
    """Igual que ``ejecutar``, sin bloquear el bucle (el servidor sigue atendiendo)."""
    proceso = await asyncio.create_subprocess_exec(
        *comando(host, puerto, *opciones), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=entorno_sin_restriccion())
    salida, _ = await asyncio.wait_for(proceso.communicate(), TIEMPO_MAXIMO_S)
    return ResultadoSClient(salida.decode("utf-8", "replace"))

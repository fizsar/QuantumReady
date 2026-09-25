"""Tipos comunes a todos los analizadores de formato."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from ..reglas import Algoritmo, clasificar


@dataclass
class Deteccion:
    linea: int
    directiva: str
    valor: str
    algoritmo: Algoritmo


@dataclass
class NoReconocido:
    linea: int
    directiva: str
    valor: str


@dataclass
class ResultadoArchivo:
    archivo: Path
    formato: str
    detecciones: list[Deteccion] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)
    no_reconocidos: list[NoReconocido] = field(default_factory=list)

    def anadir(self, linea: int, directiva: str, valor: str, *,
               clasificar_como: str | None = None,
               cbc_implicito: bool = False) -> bool:
        """Clasifica ``valor`` (o ``clasificar_como``) y registra lo detectado.

        Devuelve False y lo apunta como no reconocido si no casa con ninguna regla.
        """
        algoritmos = clasificar(clasificar_como or valor, cbc_implicito)
        if not algoritmos:
            self.no_reconocidos.append(NoReconocido(linea, directiva, valor))
            return False
        for algoritmo in algoritmos:
            self.anadir_algoritmo(linea, directiva, valor, algoritmo)
        return True

    def anadir_algoritmo(self, linea: int, directiva: str, valor: str,
                         algoritmo: Algoritmo) -> None:
        self.detecciones.append(Deteccion(linea, directiva, valor, algoritmo))

    def avisar(self, mensaje: str, linea: int | None = None) -> None:
        self.avisos.append(f"Línea {linea}: {mensaje}" if linea else mensaje)


def lineas(texto: str) -> Iterator[tuple[int, str]]:
    """Recorre las líneas no vacías sin comentarios ``#``, numeradas desde 1."""
    for n, linea in enumerate(texto.splitlines(), start=1):
        linea = linea.split("#", 1)[0].strip()
        if linea:
            yield n, linea

"""inventario.yaml: exposición y alcance de cada servicio (los marcas tú).

Formato::

    servicios:
      - nombre: bastion-ssh
        tipo: ssh            # ssh | tls | vpn
        ruta: bastion/sshd_config    # archivo o carpeta; también una lista
        exposicion: alta     # alta | baja
        alcance: alto        # alto | bajo

Las rutas relativas se resuelven respecto a la carpeta del inventario.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .riesgo import PESOS_ALCANCE, PESOS_EXPOSICION

TIPOS = ("ssh", "tls", "vpn")


class ErrorInventario(ValueError):
    pass


@dataclass(frozen=True)
class Servicio:
    nombre: str
    tipo: str
    rutas: tuple[Path, ...]
    exposicion: str
    alcance: str

    def contiene(self, archivo: Path) -> Path | None:
        """La ruta del servicio que contiene ``archivo``, o None."""
        archivo = archivo.resolve()
        for ruta in self.rutas:
            if archivo == ruta or ruta in archivo.parents:
                return ruta
        return None


@dataclass(frozen=True)
class Inventario:
    ruta: Path
    servicios: tuple[Servicio, ...]

    def servicio_de(self, archivo: Path) -> Servicio | None:
        """El servicio cuya ruta contiene el archivo (la más específica gana)."""
        candidatos = [(s, r) for s in self.servicios if (r := s.contiene(archivo))]
        if not candidatos:
            return None
        return max(candidatos, key=lambda c: len(c[1].parts))[0]


def _campo(entrada: dict, clave: str, i: int, validos=None) -> str:
    valor = entrada.get(clave)
    if valor is None or str(valor).strip() == "":
        raise ErrorInventario(f"Servicio #{i}: falta el campo '{clave}'.")
    valor = str(valor).strip()
    if validos is not None:
        valor = valor.lower()
        if valor not in validos:
            raise ErrorInventario(
                f"Servicio #{i} ({entrada.get('nombre', '?')}): '{clave}' debe ser "
                f"{' o '.join(validos)}, no '{valor}'.")
    return valor


def cargar(ruta: Path) -> Inventario:
    try:
        datos = yaml.safe_load(ruta.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise ErrorInventario(f"{ruta}: YAML no válido: {e}") from e
    entradas = datos.get("servicios") if isinstance(datos, dict) else None
    if not isinstance(entradas, list) or not entradas:
        raise ErrorInventario(f"{ruta}: se esperaba una lista 'servicios:'.")

    base = ruta.resolve().parent
    servicios = []
    for i, entrada in enumerate(entradas, start=1):
        if not isinstance(entrada, dict):
            raise ErrorInventario(f"Servicio #{i}: debe ser un diccionario.")
        rutas_crudas = entrada.get("ruta")
        if isinstance(rutas_crudas, str):
            rutas_crudas = [rutas_crudas]
        if not rutas_crudas:
            raise ErrorInventario(f"Servicio #{i}: falta el campo 'ruta'.")
        rutas = tuple((base / r).resolve() for r in rutas_crudas)
        servicios.append(Servicio(
            nombre=_campo(entrada, "nombre", i),
            tipo=_campo(entrada, "tipo", i, TIPOS),
            rutas=rutas,
            exposicion=_campo(entrada, "exposicion", i, tuple(PESOS_EXPOSICION)),
            alcance=_campo(entrada, "alcance", i, tuple(PESOS_ALCANCE)),
        ))
    return Inventario(ruta, tuple(servicios))

"""Modelo de riesgo combinado: Categoría × Exposición × Alcance (rango 0–16)."""

from __future__ import annotations

from dataclasses import dataclass

from .reglas import Categoria

PESOS_CATEGORIA = {
    Categoria.CRITICO: 4,
    Categoria.OBSOLETO: 3,
    Categoria.ADVERTENCIA: 2,
    Categoria.ACEPTABLE: 1,
    Categoria.POST_CUANTICO: 0,
}
PESOS_EXPOSICION = {"alta": 2, "baja": 1}
PESOS_ALCANCE = {"alto": 2, "bajo": 1}

# (puntuación máxima incluida, nivel)
UMBRALES = [
    (0, "Ninguno"),
    (3, "Bajo"),
    (7, "Medio"),
    (11, "Alto"),
    (16, "Urgente"),
]
NIVELES = [nivel for _, nivel in UMBRALES]


@dataclass(frozen=True)
class Riesgo:
    puntuacion: int
    nivel: str
    formula: str


def nivel_de(puntuacion: int) -> str:
    for maximo, nivel in UMBRALES:
        if puntuacion <= maximo:
            return nivel
    raise ValueError(f"Puntuación fuera de rango: {puntuacion}")


def calcular(categoria: Categoria, exposicion: str, alcance: str) -> Riesgo:
    c = PESOS_CATEGORIA[categoria]
    e = PESOS_EXPOSICION[exposicion]
    a = PESOS_ALCANCE[alcance]
    puntuacion = c * e * a
    return Riesgo(puntuacion, nivel_de(puntuacion), f"{c} × {e} × {a}")

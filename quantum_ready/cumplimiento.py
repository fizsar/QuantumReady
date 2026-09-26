"""Auditoría de cumplimiento para CI: falla si el riesgo global es Crítico.

Uso: python -m quantum_ready.cumplimiento [informe.json]

Lee el resultado del escáner (Fase 1) y calcula el nivel de riesgo global con
la misma función que usa el informe ejecutivo (Fase 4). Códigos de salida:
0 si el nivel es Alto o inferior, 1 si es Crítico, 2 si la entrada no es válida.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .informe.generador import riesgo_global

NIVEL_BLOQUEANTE = "Crítico"
MAX_URGENTES = 5


def urgentes_principales(hallazgos: list[dict], n: int = MAX_URGENTES) -> list[dict]:
    """Los ``n`` hallazgos Urgentes de mayor riesgo combinado."""
    urgentes = [h for h in hallazgos if h.get("riesgo") and h["riesgo"]["nivel"] == "Urgente"]
    return sorted(urgentes, key=lambda h: (-h["riesgo"]["puntuacion"], h["archivo"],
                                           h["linea"]))[:n]


def resumen(informe: dict) -> tuple[str, list[str]]:
    """(nivel global, líneas del resumen para el log)."""
    hallazgos = informe["hallazgos"]
    r = riesgo_global(hallazgos)
    lineas = [
        f"Nivel de riesgo global: {r.nivel}",
        f"Hallazgos: {r.conteo.get('Urgente', 0)} Urgentes, {r.conteo.get('Alto', 0)} "
        f"Altos, {r.total} elementos analizados",
    ]
    principales = urgentes_principales(hallazgos)
    if principales:
        lineas.append(f"Urgentes de mayor riesgo combinado ({len(principales)}):")
        for h in principales:
            servicio = h["servicio"] or "sin servicio"
            lineas.append(f"  [{h['riesgo']['puntuacion']:>2}] {servicio}: {h['algoritmo']} "
                          f"en {h['archivo']}:{h['linea']} ({h['directiva']}: {h['valor']})")
    return r.nivel, lineas


def main(argv: list[str] | None = None) -> int:
    for flujo in (sys.stdout, sys.stderr):
        if hasattr(flujo, "reconfigure"):
            flujo.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(
        prog="quantum_ready.cumplimiento",
        description="Falla (código 1) si el riesgo global del escaneo es Crítico.")
    p.add_argument("informe", type=Path, nargs="?", default=Path("informe.json"),
                   help="Resultado del escáner (por defecto informe.json).")
    args = p.parse_args(argv)

    try:
        informe = json.loads(args.informe.read_text(encoding="utf-8"))
        nivel, lineas = resumen(informe)
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Error: {args.informe} no es un resultado válido del escáner: {e!r}",
              file=sys.stderr)
        return 2

    print("\n".join(lineas))
    print()
    if nivel == NIVEL_BLOQUEANTE:
        mensaje = (f"Riesgo global {nivel}: hay hallazgos Urgentes. La auditoría "
                   "de cumplimiento no se supera.")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            # Anotación visible en el resumen de la ejecución de GitHub Actions
            print(f"::error title=Auditoría de cumplimiento::{mensaje}")
        print(f"FALLO: {mensaje}")
        return 1
    print(f"OK: riesgo global {nivel}; por debajo del umbral bloqueante "
          f"({NIVEL_BLOQUEANTE}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

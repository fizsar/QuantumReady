"""Línea de comandos: python -m quantum_ready [RUTAS...] [-i inventario.yaml]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .escaner import escanear
from .informe import resumen_texto
from .inventario import ErrorInventario, cargar
from .riesgo import NIVELES


def _argumentos(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="quantum_ready",
        description="Escáner de cripto-agilidad (Fase 1, modo local): detecta "
                    "algoritmos vulnerables a la computación cuántica en "
                    "archivos de configuración y certificados.")
    p.add_argument("rutas", nargs="*", type=Path,
                   help="Archivos o carpetas a escanear. Si no se indican, se "
                        "escanean todas las rutas del inventario.")
    p.add_argument("-i", "--inventario", type=Path,
                   help="inventario.yaml con exposición y alcance por servicio "
                        "(por defecto ./inventario.yaml si existe).")
    p.add_argument("-o", "--salida", default="informe.json",
                   help="Archivo JSON de salida (por defecto informe.json; '-' "
                        "para escribir el JSON por la salida estándar).")
    p.add_argument("--nivel-minimo", choices=NIVELES, default="Alto",
                   help="Nivel de riesgo a partir del cual se detalla un hallazgo "
                        "en el resumen (por defecto Alto).")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    for flujo in (sys.stdout, sys.stderr):
        if hasattr(flujo, "reconfigure"):
            flujo.reconfigure(encoding="utf-8")
    args = _argumentos(argv)

    ruta_inv = args.inventario
    if ruta_inv is None and Path("inventario.yaml").is_file():
        ruta_inv = Path("inventario.yaml")
    try:
        inventario = cargar(ruta_inv) if ruta_inv else None
    except (ErrorInventario, OSError) as e:
        print(f"Error en el inventario: {e}", file=sys.stderr)
        return 2
    if not args.rutas and inventario is None:
        print("Indica rutas a escanear o un inventario (-i inventario.yaml).",
              file=sys.stderr)
        return 2

    informe = escanear(args.rutas, inventario)
    datos = json.dumps(informe, ensure_ascii=False, indent=2)
    if args.salida == "-":
        print(datos)
        return 0

    Path(args.salida).write_text(datos + "\n", encoding="utf-8")
    print(resumen_texto(informe, args.nivel_minimo))
    print(f"\nInforme JSON completo: {args.salida}")
    return 0

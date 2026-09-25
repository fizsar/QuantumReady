"""Fase 3: overhead en red de X25519, ML-KEM-768 e híbrido sobre TCP real.

Uso: python -m quantum_ready.red [-n 100] [--perfiles fibra,4g,leo,geo]
"""

from __future__ import annotations

import argparse
import hmac
import json
import platform
import statistics
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .cliente import ejecutar_handshake
from .escenarios import ESCENARIOS, Escenario
from .servidor import ServidorHandshake

ENVIOS_POR_HANDSHAKE = 2  # Cliente → Servidor y Servidor → Cliente


@dataclass(frozen=True)
class Perfil:
    id: str
    nombre: str
    latencia_ms: float  # por tramo, aplicada en cada envío

    @property
    def etiqueta(self) -> str:
        return f"{self.nombre} ({self.latencia_ms:g} ms)"


PERFILES: dict[str, Perfil] = {
    p.id: p for p in [
        Perfil("fibra", "Fibra", 2),
        Perfil("4g", "4G", 50),
        Perfil("leo", "Satélite LEO", 25),
        Perfil("geo", "Satélite GEO", 600),
    ]
}


# --- Medición ---------------------------------------------------------------------
def medir(servidor: ServidorHandshake, escenario: Escenario, perfil: Perfil) -> dict:
    """Un handshake: tiempo de extremo a extremo, bytes y si las claves coinciden."""
    cliente = ejecutar_handshake(servidor.direccion, escenario, perfil.latencia_ms / 1000)
    lado_servidor = servidor.siguiente_resultado()
    # El Servidor deriva su clave antes de enviar la respuesta, así que cuando
    # el Cliente tiene la suya ambas partes la tienen: ese es el final.
    return {
        "escenario": escenario.id,
        "perfil": perfil.id,
        "tiempo_ms": (cliente.t_clave - cliente.t_inicio) * 1000,
        "bytes_cliente_a_servidor": cliente.bytes_enviados,
        "bytes_servidor_a_cliente": lado_servidor.bytes_enviados,
        "claves_coinciden": hmac.compare_digest(cliente.clave, lado_servidor.clave),
    }


def duracion_estimada_s(repeticiones: int, perfiles: list[Perfil],
                        escenarios: list[Escenario]) -> float:
    latencia = sum(p.latencia_ms for p in perfiles) / 1000
    return repeticiones * len(escenarios) * ENVIOS_POR_HANDSHAKE * latencia


def ejecutar_benchmark(repeticiones: int = 100,
                       perfiles: list[Perfil] | None = None,
                       escenarios: list[Escenario] | None = None,
                       calentamiento: int = 2,
                       progreso: Callable[[Perfil, int, int], None] | None = None,
                       ) -> list[dict]:
    """Devuelve una fila por ejecución medida.

    Dentro de cada perfil los escenarios se alternan (X25519, ML-KEM, híbrido,
    X25519…) para que cualquier deriva del sistema afecte a los tres por igual.
    Las ejecuciones de calentamiento no se registran.
    """
    perfiles = perfiles or list(PERFILES.values())
    escenarios = escenarios or list(ESCENARIOS.values())
    ejecuciones: list[dict] = []
    for perfil in perfiles:
        latencia_s = perfil.latencia_ms / 1000
        with ExitStack() as pila:
            servidores = {e.id: pila.enter_context(ServidorHandshake(e.id, latencia_s))
                          for e in escenarios}
            for escenario in escenarios:
                for _ in range(calentamiento):
                    medir(servidores[escenario.id], escenario, perfil)
            total = repeticiones * len(escenarios)
            for i in range(repeticiones):
                for escenario in escenarios:
                    fila = medir(servidores[escenario.id], escenario, perfil)
                    fila["iteracion"] = i
                    ejecuciones.append(fila)
                    if progreso:
                        progreso(perfil, i * len(escenarios) + escenarios.index(escenario) + 1,
                                 total)
    return ejecuciones


# --- Agregación -------------------------------------------------------------------
def _estadisticas(valores: list[float]) -> dict[str, float]:
    return {
        "media": statistics.fmean(valores),
        "desviacion": statistics.stdev(valores) if len(valores) > 1 else 0.0,
        "mediana": statistics.median(valores),
        "min": min(valores),
        "max": max(valores),
    }


def agregar(ejecuciones: list[dict], perfiles: list[Perfil],
            escenarios: list[Escenario]) -> list[dict]:
    agregados = []
    for perfil in perfiles:
        latencia_total = perfil.latencia_ms * ENVIOS_POR_HANDSHAKE
        for escenario in escenarios:
            filas = [f for f in ejecuciones
                     if f["perfil"] == perfil.id and f["escenario"] == escenario.id]
            if not filas:
                continue
            tiempos = [f["tiempo_ms"] for f in filas]
            agregados.append({
                "escenario": escenario.id,
                "perfil": perfil.id,
                "n": len(filas),
                "tiempo_ms": _estadisticas(tiempos),
                "latencia_inyectada_ms": latencia_total,
                # Lo que queda al quitar la latencia: cómputo + pila TCP local
                "tiempo_sin_latencia_ms": _estadisticas(
                    [t - latencia_total for t in tiempos]),
                "bytes": {
                    "cliente_a_servidor": filas[0]["bytes_cliente_a_servidor"],
                    "servidor_a_cliente": filas[0]["bytes_servidor_a_cliente"],
                    "total": (filas[0]["bytes_cliente_a_servidor"]
                              + filas[0]["bytes_servidor_a_cliente"]),
                },
                "claves_coinciden": sum(f["claves_coinciden"] for f in filas),
            })
    return agregados


def _porcentaje(valor: float, base: float) -> float:
    return (valor - base) / base * 100


def overhead_vs_x25519(agregados: list[dict], escenario: str = "hibrido") -> dict:
    """Overhead porcentual de ``escenario`` frente a X25519 puro, por perfil."""
    indice = {(a["escenario"], a["perfil"]): a for a in agregados}
    resultado = {}
    for (esc, perfil), a in indice.items():
        base = indice.get(("x25519", perfil))
        if esc != escenario or base is None:
            continue
        resultado[perfil] = {
            "bytes_pct": _porcentaje(a["bytes"]["total"], base["bytes"]["total"]),
            "bytes_extra": a["bytes"]["total"] - base["bytes"]["total"],
            "tiempo_pct": _porcentaje(a["tiempo_ms"]["media"], base["tiempo_ms"]["media"]),
            "tiempo_extra_ms": a["tiempo_ms"]["media"] - base["tiempo_ms"]["media"],
        }
    return resultado


def verificar_fase2(agregados: list[dict], ruta: Path | None) -> dict:
    """Comprueba que los bytes del híbrido medidos en el socket son los de la Fase 2."""
    if ruta is None or not ruta.is_file():
        return {"archivo": str(ruta) if ruta else None, "encontrado": False}
    fase2 = json.loads(ruta.read_text(encoding="utf-8"))["bytes_en_red"]
    hibrido = next((a["bytes"] for a in agregados if a["escenario"] == "hibrido"), None)
    campos = ("cliente_a_servidor", "servidor_a_cliente", "total")
    return {
        "archivo": str(ruta),
        "encontrado": True,
        "fase2": {c: fase2[c] for c in campos},
        "coincide": hibrido is not None and all(hibrido[c] == fase2[c] for c in campos),
    }


def construir_informe(ejecuciones: list[dict], perfiles: list[Perfil],
                      escenarios: list[Escenario], repeticiones: int,
                      calentamiento: int, ruta_fase2: Path | None) -> dict:
    agregados = agregar(ejecuciones, perfiles, escenarios)
    return {
        "fase": 3,
        "generado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "configuracion": {
            "repeticiones": repeticiones,
            "calentamiento": calentamiento,
            "transporte": "TCP en localhost (TCP_NODELAY), Servidor en un proceso "
                          "aparte; mensajes con prefijo de longitud de 4 bytes "
                          "(no incluido en los bytes)",
            "latencia": "por tramo, aplicada antes de cada envío; "
                        f"{ENVIOS_POR_HANDSHAKE} envíos por handshake",
            "tiempo": "desde que el Cliente empieza a generar claves (conexión TCP "
                      "ya abierta) hasta que ambas partes tienen la clave final",
            "perfiles": {p.id: {"nombre": p.nombre, "latencia_ms": p.latencia_ms}
                         for p in perfiles},
            "escenarios": {e.id: e.nombre for e in escenarios},
            "plataforma": {"python": platform.python_version(),
                           "sistema": platform.platform()},
        },
        "agregados": agregados,
        "overhead_hibrido_vs_x25519": overhead_vs_x25519(agregados),
        "verificacion_fase2": verificar_fase2(agregados, ruta_fase2),
        "ejecuciones": ejecuciones,
    }


# --- Salida -----------------------------------------------------------------------
def tabla_texto(informe: dict) -> str:
    conf = informe["configuracion"]
    perfiles = [Perfil(pid, p["nombre"], p["latencia_ms"])
                for pid, p in conf["perfiles"].items()]
    indice = {(a["escenario"], a["perfil"]): a for a in informe["agregados"]}
    ancho_esc = max(len(n) for n in conf["escenarios"].values())
    anchos = [max(len(p.etiqueta), 20) for p in perfiles]

    s = [f"TIEMPO DEL HANDSHAKE · media ± desviación ({conf['repeticiones']} "
         "ejecuciones por celda)"]
    s.append(f"{'Escenario':<{ancho_esc}}  "
             + "  ".join(f"{p.etiqueta:>{w}}" for p, w in zip(perfiles, anchos))
             + f"  {'Bytes':>6}")
    s.append("─" * len(s[-1]))
    for eid, nombre in conf["escenarios"].items():
        celdas, bytes_total = [], None
        for p, w in zip(perfiles, anchos):
            a = indice.get((eid, p.id))
            if a:
                t = a["tiempo_ms"]
                celdas.append(f"{t['media']:.2f} ± {t['desviacion']:.2f} ms".rjust(w))
                bytes_total = a["bytes"]["total"]
            else:
                celdas.append("—".rjust(w))
        s.append(f"{nombre:<{ancho_esc}}  " + "  ".join(celdas)
                 + f"  {bytes_total if bytes_total is not None else '—':>6}")

    overhead = informe["overhead_hibrido_vs_x25519"]
    if overhead:
        s.append("")
        s.append("OVERHEAD DEL HÍBRIDO FRENTE A X25519 PURO")
        ancho = max(len(p.etiqueta) for p in perfiles)
        s.append(f"{'Perfil':<{ancho}}  {'Bytes':>18}  {'Tiempo':>22}")
        s.append("─" * (ancho + 44))
        for p in perfiles:
            o = overhead.get(p.id)
            if not o:
                continue
            bytes_ = f"+{o['bytes_pct']:.0f} % (+{o['bytes_extra']} B)"
            tiempo = f"{o['tiempo_pct']:+.1f} % ({o['tiempo_extra_ms']:+.2f} ms)"
            s.append(f"{p.etiqueta:<{ancho}}  {bytes_:>18}  {tiempo:>22}")

    fallos = [a for a in informe["agregados"] if a["claves_coinciden"] != a["n"]]
    s.append("")
    total = sum(a["n"] for a in informe["agregados"])
    if fallos:
        s.append(f"❌ Claves distintas en {sum(a['n'] - a['claves_coinciden'] for a in fallos)} "
                 f"de {total} handshakes")
    else:
        s.append(f"✅ Cliente y Servidor obtienen la misma clave en los {total} handshakes")
    v = informe["verificacion_fase2"]
    if v["encontrado"]:
        s.append(f"{'✅' if v['coincide'] else '❌'} Bytes del híbrido "
                 f"{'coinciden' if v['coincide'] else 'NO coinciden'} con la Fase 2 "
                 f"({v['archivo']})")
    else:
        s.append("ℹ️  Sin resultados de la Fase 2 para contrastar los bytes "
                 "(ejecuta python -m quantum_ready.tunel)")
    return "\n".join(s)


def _argumentos(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="quantum_ready.red",
        description="Mide el overhead en red de X25519, ML-KEM-768 e híbrido "
                    "sobre TCP en localhost con latencia inyectada.")
    p.add_argument("-n", "--repeticiones", type=int, default=100,
                   help="Ejecuciones por escenario y perfil (por defecto 100).")
    p.add_argument("--perfiles", default=",".join(PERFILES),
                   help=f"Perfiles separados por comas ({', '.join(PERFILES)}).")
    p.add_argument("--calentamiento", type=int, default=2,
                   help="Ejecuciones previas no registradas por combinación.")
    p.add_argument("-o", "--salida", type=Path, default=Path("resultados_overhead.json"))
    p.add_argument("--fase2", type=Path, default=Path("resultados_intercambio.json"),
                   help="JSON de la Fase 2 con el que contrastar los bytes.")
    args = p.parse_args(argv)
    if args.repeticiones < 1:
        p.error("--repeticiones debe ser al menos 1")
    desconocidos = [x for x in args.perfiles.split(",") if x not in PERFILES]
    if desconocidos:
        p.error(f"Perfiles desconocidos: {', '.join(desconocidos)}")
    return args


def main(argv: list[str] | None = None) -> int:
    for flujo in (sys.stdout, sys.stderr):
        if hasattr(flujo, "reconfigure"):
            flujo.reconfigure(encoding="utf-8")
    args = _argumentos(argv)
    perfiles = [PERFILES[x] for x in args.perfiles.split(",")]
    escenarios = list(ESCENARIOS.values())

    estimada = duracion_estimada_s(args.repeticiones, perfiles, escenarios)
    print(f"{args.repeticiones * len(perfiles) * len(escenarios)} handshakes "
          f"({len(escenarios)} escenarios × {len(perfiles)} perfiles × "
          f"{args.repeticiones}); duración estimada ≈ {estimada / 60:.1f} min",
          file=sys.stderr)

    def progreso(perfil: Perfil, hechos: int, total: int) -> None:
        if hechos == total or hechos % 15 == 0:
            print(f"\r  {perfil.etiqueta:<24} {hechos:>4}/{total}", end="",
                  file=sys.stderr, flush=True)
            if hechos == total:
                print(file=sys.stderr)

    ejecuciones = ejecutar_benchmark(args.repeticiones, perfiles, escenarios,
                                     args.calentamiento, progreso)
    informe = construir_informe(ejecuciones, perfiles, escenarios, args.repeticiones,
                                args.calentamiento, args.fase2)
    args.salida.write_text(json.dumps(informe, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print()
    print(tabla_texto(informe))
    print(f"\nDatos crudos y agregados en {args.salida}")
    ok = all(a["claves_coinciden"] == a["n"] for a in informe["agregados"])
    v = informe["verificacion_fase2"]
    return 0 if ok and (not v["encontrado"] or v["coincide"]) else 1

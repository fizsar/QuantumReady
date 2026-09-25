"""Fase 4: informe ejecutivo en PDF a partir de los resultados de las Fases 1-3.

Uso: python -m quantum_ready.informe --idioma es|en [--salida informe.pdf]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from .datos_ejemplo import EMPRESA_EJEMPLO
from .traducciones import IDIOMAS, Traductor

PRIORITARIOS = ("Urgente", "Alto")

# Uso de cada familia de problema: lo que resuelve el intercambio híbrido
# (intercambio), lo que depende del ecosistema post-cuántico (firma) y lo que
# se arregla hoy cambiando la configuración (configuracion).
USO_POR_FAMILIA = {
    "dh": "intercambio", "ecdh": "intercambio", "rsa_intercambio": "intercambio",
    "wg_sin_psk": "intercambio", "wg_con_psk": "intercambio",
    "rsa_firma": "firma", "ecdsa": "firma", "dsa": "firma",
    "sha1": "configuracion", "md5": "configuracion", "3des": "configuracion",
    "rc4": "configuracion", "cbc": "configuracion", "tls_antiguo": "configuracion",
    "ssl": "configuracion", "aes128": "configuracion",
    # Sin regla específica: no se presenta como resuelto por la solución
    "otro": "configuracion",
}
_FAMILIA_POR_ID = {
    "DH": "dh", "ECDH": "ecdh", "ECDSA": "ecdsa", "DSA": "dsa",
    "SHA-1": "sha1", "MD5": "md5", "3DES": "3des", "RC4": "rc4",
    "TLS-1.0/1.1": "tls_antiguo", "SSL": "ssl", "AES-128": "aes128",
    "WG-SIN-PSK": "wg_sin_psk", "WG-CON-PSK": "wg_con_psk",
}
# En una suite TLS, un intercambio (EC)DH(E) delante de RSA significa que RSA
# solo autentica (firma); sin él, RSA transporta la clave de sesión.
_INTERCAMBIO_EN_SUITE = re.compile(r"(^|[-_+])(ecdhe?|e?dhe?|edh)([-_+]|$)")


class ErrorEntrada(ValueError):
    pass


# --- Carga -----------------------------------------------------------------------
@dataclass
class Entradas:
    fase1: dict
    fase2: dict
    fase3: dict
    rutas: dict[int, Path] = field(default_factory=dict)


_COMO_GENERAR = {
    1: "python -m quantum_ready -i ejemplos/inventario.yaml",
    2: "python -m quantum_ready.tunel",
    3: "python -m quantum_ready.red -o resultados_overhead.referencia.json",
}
_CLAVES_REQUERIDAS = {
    1: ("hallazgos", "resumen", "servicios"),
    2: ("tamanos_bytes", "bytes_en_red", "verificacion"),
    3: ("agregados", "overhead_hibrido_vs_x25519", "configuracion"),
}


def _cargar(fase: int, ruta: Path) -> dict:
    if not ruta.is_file():
        raise ErrorEntrada(f"No existe {ruta} (Fase {fase}). Genéralo con: "
                           f"{_COMO_GENERAR[fase]}")
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ErrorEntrada(f"{ruta}: JSON no válido: {e}") from e
    faltan = [c for c in _CLAVES_REQUERIDAS[fase] if c not in datos]
    if faltan:
        raise ErrorEntrada(f"{ruta} no parece un resultado de la Fase {fase} "
                           f"(faltan: {', '.join(faltan)}).")
    return datos


def cargar_entradas(fase1: Path, fase2: Path, fase3: Path) -> Entradas:
    datos = {n: _cargar(n, r) for n, r in ((1, fase1), (2, fase2), (3, fase3))}
    if any("algoritmo_id" not in h for h in datos[1]["hallazgos"]):
        raise ErrorEntrada(f"{fase1} es de una versión anterior del escáner (sin "
                           f"'algoritmo_id'). Vuelve a generarlo con: {_COMO_GENERAR[1]}")
    return Entradas(datos[1], datos[2], datos[3], {1: fase1, 2: fase2, 3: fase3})


# --- Riesgo global ----------------------------------------------------------------
@dataclass(frozen=True)
class RiesgoGlobal:
    nivel: str                 # Crítico | Alto | Medio | Bajo
    conteo: dict[str, int]     # por nivel de riesgo combinado
    total: int                 # elementos analizados


def riesgo_global(hallazgos: list[dict]) -> RiesgoGlobal:
    """Regla del peor caso: lo marca el hallazgo más grave, no la media."""
    conteo = Counter(h["riesgo"]["nivel"] for h in hallazgos if h.get("riesgo"))
    if conteo["Urgente"]:
        nivel = "Crítico"
    elif conteo["Alto"]:
        nivel = "Alto"
    elif conteo["Medio"]:
        nivel = "Medio"
    else:
        nivel = "Bajo"
    return RiesgoGlobal(nivel, dict(conteo), len(hallazgos))


# --- Qué resuelve la solución --------------------------------------------------------
def _rsa_transporta_la_clave(hallazgo: dict) -> bool:
    """RSA es intercambio solo en suites TLS sin (EC)DH(E): TLS_RSA_WITH_..."""
    es_suite = (hallazgo.get("formato") in ("nginx", "apache")
                and "cipher" in hallazgo["directiva"].lower())
    return es_suite and not _INTERCAMBIO_EN_SUITE.search(hallazgo["valor"].lower())


def familia(hallazgo: dict) -> str:
    id_ = hallazgo["algoritmo_id"]
    if id_.endswith("-CBC"):
        return "cbc"
    if id_ == "RSA":
        # RSA en claves de host, certificados o authby es una firma: el túnel
        # híbrido no lo resuelve aunque RSA "suene" a intercambio de claves.
        return "rsa_intercambio" if _rsa_transporta_la_clave(hallazgo) else "rsa_firma"
    return _FAMILIA_POR_ID.get(id_, "otro")


def uso(hallazgo: dict) -> str:
    return USO_POR_FAMILIA[familia(hallazgo)]


def prioritarios(hallazgos: list[dict]) -> list[dict]:
    return [h for h in hallazgos
            if h.get("riesgo") and h["riesgo"]["nivel"] in PRIORITARIOS]


def reparto_solucion(hallazgos: list[dict]) -> dict[str, list[dict]]:
    """Hallazgos prioritarios repartidos por quién los resuelve."""
    reparto: dict[str, list[dict]] = {"intercambio": [], "firma": [], "configuracion": []}
    for h in prioritarios(hallazgos):
        reparto[uso(h)].append(h)
    return reparto


@dataclass
class Grupo:
    servicio: str
    familia: str
    algoritmo: str
    nivel: str
    puntuacion: int
    casos: int


def agrupar(hallazgos: list[dict]) -> list[Grupo]:
    """Un grupo por (servicio, problema), con su peor riesgo; de mayor a menor."""
    grupos: dict[tuple[str, str], Grupo] = {}
    for h in hallazgos:
        clave = (h["servicio"], familia(h))
        r = h["riesgo"]
        g = grupos.get(clave)
        if g is None:
            grupos[clave] = Grupo(h["servicio"], clave[1], h["algoritmo"],
                                  r["nivel"], r["puntuacion"], 1)
        else:
            g.casos += 1
            if r["puntuacion"] > g.puntuacion:
                g.nivel, g.puntuacion = r["nivel"], r["puntuacion"]
    orden_uso = {"intercambio": 0, "firma": 1, "configuracion": 2}
    return sorted(grupos.values(), key=lambda g: (
        -g.puntuacion, orden_uso[USO_POR_FAMILIA[g.familia]], g.servicio, g.familia))


# --- Coste de la migración ------------------------------------------------------------
@dataclass(frozen=True)
class FilaCoste:
    perfil: str
    nombre: str
    latencia_ms: float
    actual_ms: float
    hibrido_ms: float
    extra_ms: float
    extra_pct: float


def coste_migracion(fase3: dict) -> list[FilaCoste]:
    medias = {(a["escenario"], a["perfil"]): a["tiempo_ms"]["media"]
              for a in fase3["agregados"]}
    filas = []
    for perfil, datos in fase3["configuracion"]["perfiles"].items():
        o = fase3["overhead_hibrido_vs_x25519"].get(perfil)
        if o is None:
            continue
        filas.append(FilaCoste(perfil, datos["nombre"], datos["latencia_ms"],
                               medias[("x25519", perfil)], medias[("hibrido", perfil)],
                               o["tiempo_extra_ms"], o["tiempo_pct"]))
    return filas


def encuadre_coste(filas: list[FilaCoste], t: Traductor) -> str:
    """Frase honesta sobre el coste en tiempo, derivada de los datos medidos."""
    extras = [f.extra_ms for f in filas]
    if not extras:
        return t("sin_datos")
    por_debajo = sum(1 for e in extras if e < 1)
    if por_debajo == len(extras):
        return t("coste.encuadre.todos")
    if por_debajo > len(extras) / 2:
        return t("coste.encuadre.mayoria", n=por_debajo, total=len(extras))
    return t("coste.encuadre.aprox", ms=t.numero(sum(extras) / len(extras), 1),
             min=t.numero(min(extras)), max=t.numero(max(extras)))


# --- Empresa ---------------------------------------------------------------------------
def datos_empresa(idioma: str, ruta_yaml: Path | None = None,
                  **sobrescribir: str | None) -> dict[str, str]:
    """Ejemplo por defecto < YAML < línea de comandos. Resuelve textos por idioma."""
    empresa = dict(EMPRESA_EJEMPLO)
    if ruta_yaml:
        cargado = yaml.safe_load(ruta_yaml.read_text(encoding="utf-8")) or {}
        if not isinstance(cargado, dict):
            raise ErrorEntrada(f"{ruta_yaml}: se esperaba nombre/sector/contacto.")
        empresa.update({k: v for k, v in cargado.items() if k in EMPRESA_EJEMPLO})
    empresa.update({k: v for k, v in sobrescribir.items() if v})
    return {k: (v.get(idioma) or next(iter(v.values())) if isinstance(v, dict) else str(v))
            for k, v in empresa.items()}


# --- Orquestación --------------------------------------------------------------------------
@dataclass
class Analisis:
    entradas: Entradas
    riesgo: RiesgoGlobal
    reparto: dict[str, list[dict]]
    grupos_prioritarios: list[Grupo]
    coste: list[FilaCoste]
    servicios: dict[str, dict]  # nombre -> datos del inventario (tipo, exposición...)


def analizar(entradas: Entradas) -> Analisis:
    hallazgos = entradas.fase1["hallazgos"]
    return Analisis(
        entradas=entradas,
        riesgo=riesgo_global(hallazgos),
        reparto=reparto_solucion(hallazgos),
        grupos_prioritarios=agrupar(prioritarios(hallazgos)),
        coste=coste_migracion(entradas.fase3),
        servicios={s["nombre"]: s for s in entradas.fase1["servicios"]},
    )


def generar(entradas: Entradas, idioma: str, salida: Path,
            empresa: dict[str, str], fecha: date | None = None) -> Path:
    from .maqueta import construir_pdf  # reportlab solo hace falta aquí

    t = Traductor(idioma)
    construir_pdf(analizar(entradas), t, empresa, salida, fecha or date.today())
    return salida


def _argumentos(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="quantum_ready.informe",
        description="Genera el informe ejecutivo en PDF a partir de las Fases 1-3.")
    p.add_argument("--idioma", required=True, choices=IDIOMAS)
    p.add_argument("--salida", type=Path,
                   help="Ruta del PDF (por defecto informe_ejecutivo_<idioma>.pdf).")
    p.add_argument("--fase1", type=Path, default=Path("informe.json"))
    p.add_argument("--fase2", type=Path, default=Path("resultados_intercambio.json"))
    p.add_argument("--fase3", type=Path,
                   default=Path("resultados_overhead.referencia.json"))
    p.add_argument("--empresa", type=Path,
                   help="YAML con nombre, sector y contacto de la empresa.")
    p.add_argument("--empresa-nombre")
    p.add_argument("--empresa-sector")
    p.add_argument("--empresa-contacto")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    for flujo in (sys.stdout, sys.stderr):
        if hasattr(flujo, "reconfigure"):
            flujo.reconfigure(encoding="utf-8")
    args = _argumentos(argv)
    salida = args.salida or Path(f"informe_ejecutivo_{args.idioma}.pdf")
    try:
        entradas = cargar_entradas(args.fase1, args.fase2, args.fase3)
        empresa = datos_empresa(args.idioma, args.empresa,
                                nombre=args.empresa_nombre, sector=args.empresa_sector,
                                contacto=args.empresa_contacto)
    except (ErrorEntrada, OSError, yaml.YAMLError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    generar(entradas, args.idioma, salida, empresa)
    print(f"Informe generado: {salida}")
    return 0

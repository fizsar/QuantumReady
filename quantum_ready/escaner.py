"""Orquesta el escaneo: archivos -> detecciones -> hallazgos con riesgo combinado."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .inventario import Inventario, Servicio
from .parsers import analizar_archivo
from .reglas import Categoria
from .riesgo import NIVELES, calcular


def _mostrar(ruta: Path) -> str:
    """Ruta relativa al directorio actual si es posible, con barras '/'."""
    try:
        return ruta.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return ruta.resolve().as_posix()


def _expandir(ruta: Path) -> list[Path]:
    if ruta.is_dir():
        return sorted(p for p in ruta.rglob("*") if p.is_file())
    return [ruta]


def _objetivos(rutas: list[Path], inventario: Inventario | None,
               avisos: list[dict]) -> list[tuple[Path, Servicio | None, bool]]:
    """(archivo, servicio, fue_pedido_explicitamente) sin duplicados."""
    if rutas:
        raices = [(r, None) for r in rutas]
    elif inventario:
        raices = [(r, s) for s in inventario.servicios for r in s.rutas]
    else:
        raices = []

    vistos: set[Path] = set()
    objetivos = []
    for raiz, servicio in raices:
        if not raiz.exists():
            avisos.append({"archivo": _mostrar(raiz), "mensaje": "La ruta no existe."})
            continue
        for archivo in _expandir(raiz):
            clave = archivo.resolve()
            if clave in vistos:
                continue
            vistos.add(clave)
            propio = servicio or (inventario.servicio_de(archivo) if inventario else None)
            objetivos.append((archivo, propio, archivo == raiz))
    return objetivos


def escanear(rutas: list[Path], inventario: Inventario | None = None) -> dict:
    """Escanea las rutas (o, si no hay, todas las del inventario) y devuelve el informe."""
    avisos: list[dict] = []
    hallazgos: list[dict] = []
    no_reconocidos: list[dict] = []
    archivos_por_servicio: Counter[str] = Counter()
    escaneados = omitidos = 0

    for archivo, servicio, explicito in _objetivos(rutas, inventario, avisos):
        nombre_archivo = _mostrar(archivo)
        try:
            resultado = analizar_archivo(archivo)
        except OSError as e:
            avisos.append({"archivo": nombre_archivo, "mensaje": f"No se pudo leer: {e}"})
            continue
        if resultado is None:
            omitidos += 1
            if explicito:
                avisos.append({"archivo": nombre_archivo,
                               "mensaje": "Formato no reconocido; archivo omitido."})
            continue

        escaneados += 1
        if servicio:
            archivos_por_servicio[servicio.nombre] += 1
        else:
            avisos.append({"archivo": nombre_archivo, "mensaje":
                           "No pertenece a ningún servicio del inventario: riesgo "
                           "combinado sin evaluar (marca exposición y alcance en "
                           "inventario.yaml)."})

        for aviso in resultado.avisos:
            avisos.append({"archivo": nombre_archivo, "mensaje": aviso})
        for nr in resultado.no_reconocidos:
            no_reconocidos.append({"archivo": nombre_archivo, "linea": nr.linea,
                                   "directiva": nr.directiva, "valor": nr.valor})
        for d in resultado.detecciones:
            alg = d.algoritmo
            riesgo = None
            if servicio:
                r = calcular(alg.categoria, servicio.exposicion, servicio.alcance)
                riesgo = {"puntuacion": r.puntuacion, "nivel": r.nivel,
                          "formula": r.formula}
            hallazgos.append({
                "servicio": servicio.nombre if servicio else None,
                "archivo": nombre_archivo,
                "formato": resultado.formato,
                "linea": d.linea,
                "directiva": d.directiva,
                "valor": d.valor,
                "algoritmo": alg.nombre,
                "categoria": alg.categoria.value,
                "riesgo": riesgo,
                "recomendacion": alg.recomendacion,
                "motivo": alg.motivo,
            })

    hallazgos.sort(key=lambda h: (-(h["riesgo"]["puntuacion"] if h["riesgo"] else -1),
                                  h["archivo"], h["linea"]))

    servicios = []
    if inventario:
        for s in inventario.servicios:
            propios = [h for h in hallazgos if h["servicio"] == s.nombre]
            peor = max(propios, key=lambda h: h["riesgo"]["puntuacion"], default=None)
            servicios.append({
                "nombre": s.nombre,
                "tipo": s.tipo,
                "exposicion": s.exposicion,
                "alcance": s.alcance,
                "archivos": archivos_por_servicio[s.nombre],
                "hallazgos": len(propios),
                "riesgo_maximo": peor["riesgo"] if peor else None,
                "por_categoria": _contar_categorias(propios),
            })
        servicios.sort(key=lambda s: -(s["riesgo_maximo"]["puntuacion"]
                                       if s["riesgo_maximo"] else -1))

    niveles = Counter(h["riesgo"]["nivel"] for h in hallazgos if h["riesgo"])
    return {
        "herramienta": "quantum-ready",
        "version": __version__,
        "fase": 1,
        "generado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "inventario": _mostrar(inventario.ruta) if inventario else None,
        "resumen": {
            "archivos_escaneados": escaneados,
            "archivos_omitidos": omitidos,
            "hallazgos": len(hallazgos),
            "por_categoria": _contar_categorias(hallazgos),
            "por_nivel": {n: niveles[n] for n in reversed(NIVELES)},
            "sin_evaluar": sum(1 for h in hallazgos if not h["riesgo"]),
        },
        "servicios": servicios,
        "hallazgos": hallazgos,
        "avisos": avisos,
        "no_reconocidos": no_reconocidos,
    }


def _contar_categorias(hallazgos: list[dict]) -> dict[str, int]:
    conteo = Counter(h["categoria"] for h in hallazgos)
    return {c.value: conteo[c.value] for c in Categoria}

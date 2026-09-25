"""Resumen legible a partir del informe JSON."""

from __future__ import annotations

from .reglas import Categoria
from .riesgo import NIVELES

MAX_UBICACIONES = 4


def _categorias(conteo: dict[str, int], con_nombre: bool = False) -> str:
    partes = []
    for c in Categoria:
        n = conteo.get(c.value, 0)
        if n or con_nombre:
            partes.append(f"{c.emoji} {c.etiqueta} {n}" if con_nombre else f"{c.emoji} {n}")
    return "   ".join(partes) or "—"


def _agrupar(hallazgos: list[dict]) -> list[list[dict]]:
    """Agrupa por (servicio, algoritmo, riesgo) conservando el orden."""
    grupos: dict[tuple, list[dict]] = {}
    for h in hallazgos:
        r = h["riesgo"]
        clave = (h["servicio"], h["algoritmo"], r["puntuacion"] if r else None)
        grupos.setdefault(clave, []).append(h)
    return list(grupos.values())


def _bloque(grupo: list[dict]) -> list[str]:
    h = grupo[0]
    cat = Categoria(h["categoria"])
    r = h["riesgo"]
    cabecera = f"[{r['nivel']} {r['puntuacion']}]" if r else "[sin evaluar]"
    servicio = f" · {h['servicio']}" if h["servicio"] else ""
    lineas = [f"  {cabecera} {cat.emoji} {h['algoritmo']}{servicio}"]
    for u in grupo[:MAX_UBICACIONES]:
        lineas.append(f"      {u['archivo']}:{u['linea']}  {u['directiva']}: {u['valor']}")
    if len(grupo) > MAX_UBICACIONES:
        lineas.append(f"      … y {len(grupo) - MAX_UBICACIONES} ubicaciones más")
    lineas.append(f"      → {h['recomendacion']}")
    lineas.append(f"      Por qué: {h['motivo']}")
    return lineas


def resumen_texto(informe: dict, nivel_minimo: str = "Alto") -> str:
    res = informe["resumen"]
    s: list[str] = []
    s.append("QUANTUM READY · Informe de cripto-agilidad (Fase 1)")
    origen = f"Inventario: {informe['inventario']} · " if informe["inventario"] else ""
    s.append(f"{origen}{res['archivos_escaneados']} archivos escaneados · "
             f"{res['hallazgos']} hallazgos")
    s.append("")
    s.append(f"Por categoría:  {_categorias(res['por_categoria'], con_nombre=True)}")
    niveles = "   ".join(f"{n} {c}" for n, c in res["por_nivel"].items())
    s.append(f"Por riesgo:     {niveles}")
    if res["sin_evaluar"]:
        s.append(f"Sin evaluar:    {res['sin_evaluar']} (archivos fuera del inventario)")

    if informe["servicios"]:
        s.append("")
        s.append("SERVICIOS (ordenados por riesgo máximo)")
        ancho = max(len(sv["nombre"]) for sv in informe["servicios"])
        for sv in informe["servicios"]:
            r = sv["riesgo_maximo"]
            riesgo = f"{r['nivel']} {r['puntuacion']}" if r else "—"
            s.append(f"  {riesgo:<11} {sv['nombre']:<{ancho}}  {sv['tipo']:<3}  "
                     f"exposición {sv['exposicion']} · alcance {sv['alcance']:<4}  "
                     f"{_categorias(sv['por_categoria'])}")

    umbral = NIVELES.index(nivel_minimo)
    prioritarios = [h for h in informe["hallazgos"]
                    if h["riesgo"] and NIVELES.index(h["riesgo"]["nivel"]) >= umbral]
    s.append("")
    titulo = "PRIORIDADES" if nivel_minimo != NIVELES[0] else "TODOS LOS HALLAZGOS"
    s.append(f"{titulo} (riesgo {nivel_minimo} o superior)")
    if not prioritarios:
        s.append("  Ninguno.")
    for grupo in _agrupar(prioritarios):
        s.extend(_bloque(grupo))

    sin_evaluar = [h for h in informe["hallazgos"] if not h["riesgo"]
                   and h["categoria"] not in ("aceptable", "post_cuantico")]
    if sin_evaluar:
        s.append("")
        s.append("SIN EVALUAR (fuera del inventario; solo categorías de riesgo)")
        for grupo in _agrupar(sin_evaluar):
            s.extend(_bloque(grupo))

    avisos = list(dict.fromkeys(f"{a['archivo']}: {a['mensaje']}"
                                for a in informe["avisos"]))
    if avisos:
        s.append("")
        s.append("AVISOS")
        s.extend(f"  - {a}" for a in avisos)

    if informe["no_reconocidos"]:
        s.append("")
        s.append(f"NO RECONOCIDOS ({len(informe['no_reconocidos'])}; sin regla en el "
                 "libro, revisar a mano)")
        for nr in informe["no_reconocidos"][:10]:
            s.append(f"  - {nr['archivo']}:{nr['linea']}  {nr['directiva']}: {nr['valor']}")
        if len(informe["no_reconocidos"]) > 10:
            s.append(f"  … y {len(informe['no_reconocidos']) - 10} más (ver JSON)")
    return "\n".join(s)

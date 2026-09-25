"""Construcción del PDF con reportlab. Todos los textos vienen del Traductor.

Cada una de las 7 secciones deja una entrada en el índice (outline) del PDF,
que es lo que usan los tests para comprobar la estructura.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (Flowable, KeepTogether, ListFlowable, ListItem,
                                PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

from ..reglas import ALGORITMOS
from .generador import Analisis, agrupar, encuadre_coste
from .traducciones import ALGORITMOS_NEUTROS, Traductor

MARGEN = 2.2 * cm
ANCHO = A4[0] - 2 * MARGEN

AZUL = colors.HexColor("#1F3A5F")
GRIS = colors.HexColor("#5B6573")
GRIS_CLARO = colors.HexColor("#EEF1F5")
LINEA = colors.HexColor("#C9D1DC")
VERDE = colors.HexColor("#067647")
ROJO = colors.HexColor("#B42318")
COLOR_NIVEL = {
    "Crítico": ROJO, "Urgente": ROJO,
    "Alto": colors.HexColor("#C4320A"),
    "Medio": colors.HexColor("#B54708"),
    "Bajo": VERDE, "Ninguno": GRIS,
}
SECCIONES = ("portada", "resumen", "hallazgos", "solucion", "coste", "pendiente",
             "apendice")

# Las fuentes estándar de PDF (Helvetica) no tienen estos caracteres
_SUSTITUCIONES = {"→": "->", "≈": "~"}


def _seguro(texto: str) -> str:
    for original, sustituto in _SUSTITUCIONES.items():
        texto = texto.replace(original, sustituto)
    return texto


def _p(texto: str, estilo: ParagraphStyle, escapar: bool = True) -> Paragraph:
    texto = _seguro(texto)
    return Paragraph(escape(texto) if escapar else texto, estilo)


# --- Estilos ------------------------------------------------------------------------
def _estilos() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle("base", fontName="Helvetica", fontSize=10, leading=14.5,
                          textColor=colors.HexColor("#1D2530"), spaceAfter=7)
    return {
        "base": base,
        "seccion": ParagraphStyle("seccion", parent=base, fontName="Helvetica-Bold",
                                  fontSize=17, leading=21, textColor=AZUL,
                                  spaceBefore=4, spaceAfter=12),
        "sub": ParagraphStyle("sub", parent=base, fontName="Helvetica-Bold",
                              fontSize=11.5, leading=15, textColor=AZUL,
                              spaceBefore=10, spaceAfter=6),
        "nota": ParagraphStyle("nota", parent=base, fontSize=8.5, leading=12,
                               textColor=GRIS, fontName="Helvetica-Oblique"),
        "celda": ParagraphStyle("celda", parent=base, fontSize=8.5, leading=11,
                                spaceAfter=0),
        "celda_b": ParagraphStyle("celda_b", parent=base, fontSize=8.5, leading=11,
                                  spaceAfter=0, fontName="Helvetica-Bold"),
        "celda_cab": ParagraphStyle("celda_cab", parent=base, fontSize=8.5,
                                    leading=11, spaceAfter=0,
                                    fontName="Helvetica-Bold", textColor=colors.white),
        "mini": ParagraphStyle("mini", parent=base, fontSize=7, leading=8.8,
                               spaceAfter=0),
        # Rutas y valores largos sin espacios: se pueden partir en cualquier punto
        "mini_corte": ParagraphStyle("mini_corte", parent=base, fontSize=7,
                                     leading=8.8, spaceAfter=0, wordWrap="CJK"),
        "mini_cab": ParagraphStyle("mini_cab", parent=base, fontSize=7, leading=8.8,
                                   spaceAfter=0, fontName="Helvetica-Bold",
                                   textColor=colors.white),
        "titulo": ParagraphStyle("titulo", parent=base, fontName="Helvetica-Bold",
                                 fontSize=26, leading=32, textColor=AZUL,
                                 spaceAfter=14),
        "subtitulo": ParagraphStyle("subtitulo", parent=base, fontSize=13,
                                    leading=18, textColor=GRIS, spaceAfter=30),
        "cifra": ParagraphStyle("cifra", parent=base, fontName="Helvetica-Bold",
                                fontSize=22, leading=26, alignment=TA_CENTER,
                                spaceAfter=2),
        "cifra_txt": ParagraphStyle("cifra_txt", parent=base, fontSize=8.5,
                                    leading=11, alignment=TA_CENTER, spaceAfter=0,
                                    textColor=GRIS),
    }


# --- Piezas ---------------------------------------------------------------------------
class Marcador(Flowable):
    """Entrada del índice del PDF; no ocupa espacio."""

    def __init__(self, clave: str, titulo: str):
        super().__init__()
        self.clave, self.titulo = clave, _seguro(titulo)

    def wrap(self, *args):
        return 0, 0

    def draw(self):
        self.canv.bookmarkPage(self.clave)
        self.canv.addOutlineEntry(self.titulo, self.clave, level=0)


def _seccion(clave: str, t: Traductor, e: dict) -> list:
    titulo = t(f"seccion.{clave}")
    return [Marcador(clave, titulo), _p(titulo, e["seccion"])]


def _tabla(filas: list[list], anchos: list[float], cabecera: bool = True,
           fondos: dict[int, colors.Color] | None = None) -> Table:
    tabla = Table(filas, colWidths=anchos, repeatRows=1 if cabecera else 0)
    estilo = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINEA),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if cabecera:
        estilo.append(("BACKGROUND", (0, 0), (-1, 0), AZUL))
    for fila, color in (fondos or {}).items():
        estilo.append(("BACKGROUND", (0, fila), (0, fila), color))
    tabla.setStyle(TableStyle(estilo))
    return tabla


def _cabecera(textos: list[str], estilo: ParagraphStyle) -> list[Paragraph]:
    return [_p(x, estilo) for x in textos]


class Marca(Flowable):
    """✔ verde o ✘ rojo dibujados como vectores: no dependen de ninguna fuente."""

    def __init__(self, ok: bool, tam: float = 10):
        super().__init__()
        self.ok, self.tam = ok, tam

    def wrap(self, *args):
        return self.tam, self.tam

    def draw(self):
        c, r = self.canv, self.tam / 2
        c.setFillColor(VERDE if self.ok else ROJO)
        c.circle(r, r, r, stroke=0, fill=1)
        c.setStrokeColor(colors.white)
        c.setLineWidth(1.4)
        c.setLineCap(1)
        if self.ok:
            c.lines([(r * 0.5, r * 1.0, r * 0.85, r * 0.62),
                     (r * 0.85, r * 0.62, r * 1.5, r * 1.4)])
        else:
            c.lines([(r * 0.6, r * 0.6, r * 1.4, r * 1.4),
                     (r * 0.6, r * 1.4, r * 1.4, r * 0.6)])


def _marca(ok: bool, texto: str, e: dict, ancho: float = ANCHO) -> Table:
    tabla = Table([[Marca(ok), _p(texto, e["base"])]],
                  colWidths=[0.6 * cm, ancho - 0.6 * cm])
    tabla.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (0, 0), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return tabla


def nombre_algoritmo(id_: str, t: Traductor, respaldo: str | None = None) -> str:
    """Nombre del algoritmo en el idioma del informe, a partir de su id.

    Nunca usa el nombre en castellano del escáner salvo que el algoritmo sea
    neutro (ALGORITMOS_NEUTROS). ``respaldo`` solo se usa con ids desconocidos
    (un informe.json de otra versión del escáner).
    """
    if id_.endswith("-CBC"):
        return t("tecnico.cbc", base=nombre_algoritmo(id_[:-len("-CBC")], t, respaldo))
    if id_ in ALGORITMOS_NEUTROS and id_ in ALGORITMOS:
        return ALGORITMOS[id_].nombre
    if t.existe(f"tecnico.{id_}"):
        return t(f"tecnico.{id_}")
    return respaldo or id_


def _directiva(directiva: str, t: Traductor) -> str:
    clave = f"tecnico.directiva.{directiva}"
    return t(clave) if t.existe(clave) else directiva


def _perfil(fila_o_id, nombre: str, latencia_ms: float, t: Traductor) -> str:
    clave = f"perfil.{fila_o_id}"
    nombre = t(clave) if t.existe(clave) else nombre
    return t("perfil.latencia", nombre=nombre, ms=t.numero(latencia_ms, 0))


def _texto_familia(fam: str, parte: str, algoritmo: str, t: Traductor) -> str:
    return t(f"familia.{fam}.{parte}", algoritmo=algoritmo) if fam == "otro" \
        else t(f"familia.{fam}.{parte}")


# --- Secciones ------------------------------------------------------------------------
def _portada(a: Analisis, t: Traductor, empresa: dict, fecha: date, e: dict) -> list:
    datos = [
        (t("portada.preparado_para"), empresa["nombre"]),
        (t("portada.sector"), empresa["sector"]),
        (t("portada.contacto"), empresa["contacto"]),
        (t("portada.fecha"), t.fecha(fecha.day, fecha.month, fecha.year)),
    ]
    filas = [[_p(k, e["celda_b"]), _p(v, e["base"])] for k, v in datos]
    tabla = Table(filas, colWidths=[4 * cm, ANCHO - 4 * cm])
    tabla.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINEA),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    nivel = a.riesgo.nivel
    insignia = _insignia(f"{t('resumen.nivel')}: {t(f'global.{nivel}')}", nivel, e)
    return [
        Marcador("portada", t("seccion.portada")),
        Spacer(1, 3.5 * cm),
        _p(t("titulo"), e["titulo"]),
        _p(t("portada.subtitulo"), e["subtitulo"]),
        tabla,
        Spacer(1, 1.2 * cm),
        insignia,
        Spacer(1, 5 * cm),
        _p(t("portada.confidencial"), e["nota"]),
        PageBreak(),
    ]


def _insignia(texto: str, nivel: str, e: dict) -> Table:
    estilo = ParagraphStyle("insignia", parent=e["base"], fontName="Helvetica-Bold",
                            fontSize=14, leading=18, textColor=colors.white,
                            alignment=TA_CENTER, spaceAfter=0)
    tabla = Table([[_p(texto, estilo)]], colWidths=[ANCHO])
    tabla.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_NIVEL[nivel]),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    return tabla


def _resumen(a: Analisis, t: Traductor, e: dict) -> list:
    r = a.riesgo
    conteo = t("resumen.conteo",
               urgentes=t.plural("nivel.Urgente", r.conteo.get("Urgente", 0)),
               altos=t.plural("nivel.Alto", r.conteo.get("Alto", 0)),
               total=r.total, servicios=len(a.servicios))
    partes = _seccion("resumen", t, e) + [
        _insignia(f"{t('resumen.nivel')}: {t(f'global.{r.nivel}')}", r.nivel, e),
        Spacer(1, 8),
        _p(conteo, e["sub"]),
        _p(t(f"resumen.significa.{r.nivel}"), e["base"]),
        _p(t("resumen.regla"), e["nota"]),
    ]

    reparto = a.reparto
    total = sum(len(v) for v in reparto.values())
    if total:
        cifras = [
            (len(reparto["intercambio"]), VERDE),
            (len(reparto["configuracion"]), AZUL),
            (len(reparto["firma"]), colors.HexColor("#B54708")),
        ]
        etiquetas = [t(f"resumen.cifra.{u}")
                     for u in ("intercambio", "configuracion", "firma")]
        celdas = [[_p(str(n), ParagraphStyle("c", parent=e["cifra"], textColor=c))
                   for n, c in cifras],
                  [_p(x, e["cifra_txt"]) for x in etiquetas]]
        tabla = Table(celdas, colWidths=[ANCHO / 3] * 3)
        tabla.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), GRIS_CLARO),
            ("LINEAFTER", (0, 0), (1, -1), 2, colors.white),
            ("TOPPADDING", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
        ]))
        partes += [Spacer(1, 6), tabla, Spacer(1, 10),
                   _p(t("resumen.solucion", prioritarios=total,
                        intercambio=len(reparto["intercambio"]),
                        configuracion=len(reparto["configuracion"]),
                        firma=len(reparto["firma"])), e["base"])]
    else:
        partes.append(_p(t("resumen.sin_prioritarios"), e["base"]))

    partes.append(_p(t("resumen.coste", encuadre=encuadre_coste(a.coste, t),
                       kb=t.numero(_bytes_extra(a) / 1024, 1)), e["base"]))
    partes.append(PageBreak())
    return partes


def _servicio_celda(nombre: str | None, a: Analisis, t: Traductor, e: dict) -> Paragraph:
    s = a.servicios.get(nombre or "", {})
    detalle = []
    if s.get("tipo"):
        detalle.append(t(f"servicio.tipo.{s['tipo']}"))
    if s.get("exposicion"):
        detalle.append(t(f"servicio.exposicion.{s['exposicion']}"))
    texto = f"<b>{escape(_seguro(nombre or t('sin_datos')))}</b>"
    if detalle:
        texto += f'<br/><font size="7.5" color="#5B6573">{escape(" · ".join(detalle))}</font>'
    return Paragraph(texto, e["celda"])


def _hallazgos(a: Analisis, t: Traductor, e: dict) -> list:
    partes = _seccion("hallazgos", t, e) + [_p(t("hallazgos.intro"), e["base"])]
    if not a.grupos_prioritarios:
        return partes + [_p(t("hallazgos.ninguno"), e["base"]), PageBreak()]

    blanco = ParagraphStyle("pri", parent=e["celda_b"], textColor=colors.white)
    filas = [_cabecera([t(f"hallazgos.col.{c}") for c in
                        ("prioridad", "servicio", "que", "hacer", "casos")], e["celda_cab"])]
    fondos = {}
    for i, g in enumerate(a.grupos_prioritarios, start=1):
        fondos[i] = COLOR_NIVEL[g.nivel]
        filas.append([
            _p(t(f"nivel.{g.nivel}"), blanco),
            _servicio_celda(g.servicio, a, t, e),
            _p(_texto_familia(g.familia, "que", g.algoritmo, t), e["celda"]),
            _p(_texto_familia(g.familia, "hacer", g.algoritmo, t), e["celda"]),
            _p(str(g.casos), e["celda"]),
        ])
    anchos = [1.9 * cm, 3.4 * cm, 5.2 * cm, 4.7 * cm, 1.4 * cm]
    anchos[2] += ANCHO - sum(anchos)
    return partes + [_tabla(filas, anchos, fondos=fondos), PageBreak()]


def _solucion(a: Analisis, t: Traductor, e: dict) -> list:
    v = a.entradas.fase2["verificacion"]
    interior = ANCHO - 24  # menos el relleno de la caja
    if v["atacante_coincide"]:
        atacante = _marca(False, t("solucion.ko_atacante"), e, interior)
    elif "intentos_atacante" in v:
        atacante = _marca(True, t("solucion.ok_atacante", n=v["intentos_atacante"]), e,
                          interior)
    else:
        atacante = _marca(True, t("solucion.ok_atacante_sin_n"), e, interior)
    coinciden = v["cliente_servidor_coinciden"]
    caja = Table([[[
        _p(t("solucion.prueba"), e["sub"]),
        _marca(coinciden, t("solucion.ok_coinciden" if coinciden
                            else "solucion.ko_coinciden"), e, interior),
        Spacer(1, 4),
        atacante,
    ]]], colWidths=[ANCHO])
    caja.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), GRIS_CLARO),
                              ("LEFTPADDING", (0, 0), (-1, -1), 12),
                              ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                              ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    return _seccion("solucion", t, e) + [
        _p(t("solucion.p1"), e["base"]),
        _p(t("solucion.p2"), e["base"]),
        Spacer(1, 6),
        caja,
        PageBreak(),
    ]


def _bytes_por_escenario(a: Analisis) -> dict[str, int]:
    return {ag["escenario"]: ag["bytes"]["total"] for ag in a.entradas.fase3["agregados"]}


def _bytes_extra(a: Analisis) -> int:
    b = _bytes_por_escenario(a)
    return b.get("hibrido", 0) - b.get("x25519", 0)


def _coste(a: Analisis, t: Traductor, e: dict) -> list:
    n = a.entradas.fase3["configuracion"]["repeticiones"]
    filas = [_cabecera([t(f"coste.col.{c}") for c in
                        ("red", "actual", "hibrido", "diferencia")], e["celda_cab"])]
    for f in a.coste:
        filas.append([
            _p(_perfil(f.perfil, f.nombre, f.latencia_ms, t), e["celda"]),
            _p(f"{t.numero(f.actual_ms)} ms", e["celda"]),
            _p(f"{t.numero(f.hibrido_ms)} ms", e["celda"]),
            _p(f"+{t.numero(f.extra_ms)} ms (+{t.numero(f.extra_pct, 1)} %)",
               e["celda_b"]),
        ])
    anchos = [6.2 * cm, 3.2 * cm, 3.2 * cm]
    anchos.append(ANCHO - sum(anchos))
    b = _bytes_por_escenario(a)
    return _seccion("coste", t, e) + [
        _p(t("coste.intro", n=n), e["base"]),
        _tabla(filas, anchos),
        Spacer(1, 10),
        _p(t("coste.conclusion", encuadre=encuadre_coste(a.coste, t)), e["sub"]),
        _p(t("coste.bytes", extra=_bytes_extra(a), hibrido=b.get("hibrido", 0),
             actual=b.get("x25519", 0), kb=t.numero(_bytes_extra(a) / 1024, 1)),
           e["base"]),
        _p(t("coste.nota"), e["nota"]),
        PageBreak(),
    ]


def _pendiente(a: Analisis, t: Traductor, e: dict) -> list:
    firmas = a.reparto["firma"]
    partes = _seccion("pendiente", t, e) + [
        _p(t("pendiente.p1"), e["base"]),
        _p(t("pendiente.p2"), e["base"]),
    ]
    if firmas:
        partes.append(_p(t("pendiente.firmas", n=len(firmas)), e["celda_b"]))
        partes.append(Spacer(1, 4))
        filas = [_cabecera([t(f"pendiente.col.{c}") for c in ("servicio", "que", "casos")],
                           e["celda_cab"])]
        for g in agrupar(firmas):
            filas.append([_servicio_celda(g.servicio, a, t, e),
                          _p(_texto_familia(g.familia, "que", g.algoritmo, t), e["celda"]),
                          _p(str(g.casos), e["celda"])])
        anchos = [4.2 * cm, 0, 1.4 * cm]
        anchos[1] = ANCHO - anchos[0] - anchos[2]
        partes.append(_tabla(filas, anchos))
    else:
        partes.append(_p(t("pendiente.sin_firmas"), e["base"]))
    configuracion = a.reparto["configuracion"]
    if configuracion:
        partes += [Spacer(1, 8), _p(t("pendiente.configuracion", n=len(configuracion)),
                                    e["base"])]
    pasos = ListFlowable(
        [ListItem(_p(t(f"pendiente.paso{i}"), e["base"])) for i in (1, 2, 3)],
        bulletType="1", bulletFontName="Helvetica-Bold", bulletColor=AZUL)
    partes += [KeepTogether([_p(t("pendiente.pasos"), e["sub"]), pasos]), PageBreak()]
    return partes


def _apendice(a: Analisis, t: Traductor, e: dict) -> list:
    ent = a.entradas
    partes = _seccion("apendice", t, e) + [
        _p(t("apendice.intro"), e["base"]),
        _p(t("apendice.fuentes"), e["sub"]),
    ]
    for fase, datos in ((1, ent.fase1), (2, ent.fase2), (3, ent.fase3)):
        partes.append(_p(t("apendice.fuente", fase=fase,
                           archivo=ent.rutas.get(fase, "?"),
                           fecha=str(datos.get("generado", "?"))[:10]), e["celda"]))

    # A.1 Fase 1
    hallazgos = ent.fase1["hallazgos"]
    res = ent.fase1["resumen"]
    partes += [_p(t("apendice.fase1"), e["sub"]),
               _p(t("apendice.fase1.resumen", hallazgos=len(hallazgos),
                    archivos=res["archivos_escaneados"], sin_evaluar=res["sin_evaluar"]),
                  e["nota"])]
    filas = [_cabecera([t(f"apendice.col.{c}") for c in
                        ("riesgo", "categoria", "servicio", "ubicacion", "algoritmo",
                         "valor")], e["mini_cab"])]
    for h in hallazgos:
        r = h["riesgo"]
        riesgo = (f"{t('nivel.' + r['nivel'])} ({r['puntuacion']})" if r
                  else t("sin_datos"))
        filas.append([
            _p(riesgo, e["mini"]),
            _p(t(f"categoria.{h['categoria']}"), e["mini"]),
            _p(h["servicio"] or t("sin_datos"), e["mini"]),
            _p(f"{h['archivo']}:{h['linea']}", e["mini_corte"]),
            _p(nombre_algoritmo(h["algoritmo_id"], t, h["algoritmo"]), e["mini"]),
            _p(f"{_directiva(h['directiva'], t)}: {h['valor']}", e["mini_corte"]),
        ])
    anchos = [1.7 * cm, 2.3 * cm, 2.0 * cm, 3.6 * cm, 3.1 * cm]
    anchos.append(ANCHO - sum(anchos))
    partes.append(_tabla(filas, anchos))

    # A.2 Fase 2
    f2 = ent.fase2
    filas = [_cabecera([t("apendice.col.elemento"), t("apendice.col.bytes")], e["celda_cab"])]
    for clave, valor in list(f2["tamanos_bytes"].items()) + list(f2["bytes_en_red"].items()):
        nombre = t(f"apendice.elem.{clave}") if t.existe(f"apendice.elem.{clave}") else clave
        filas.append([_p(nombre, e["celda"]), _p(str(valor), e["celda"])])
    v = f2["verificacion"]
    partes += [
        _p(t("apendice.fase2"), e["sub"]),
        _p(t("apendice.fase2.esquema", esquema=f2.get("esquema", "?")), e["nota"]),
        _tabla(filas, [8 * cm, 3 * cm]),
        Spacer(1, 8),
        _marca(v["cliente_servidor_coinciden"],
               t("solucion.ok_coinciden" if v["cliente_servidor_coinciden"]
                 else "solucion.ko_coinciden"), e),
        _marca(not v["atacante_coincide"],
               t("solucion.ko_atacante") if v["atacante_coincide"] else
               t("solucion.ok_atacante", n=v["intentos_atacante"])
               if "intentos_atacante" in v else t("solucion.ok_atacante_sin_n"), e),
        Spacer(1, 4),
    ]

    # A.3 Fase 3
    f3 = ent.fase3
    conf = f3["configuracion"]
    plataforma = conf.get("plataforma", {})
    partes += [
        _p(t("apendice.fase3"), e["sub"]),
        _p(t("apendice.fase3.config", n=conf["repeticiones"],
             calentamiento=conf.get("calentamiento", "?"),
             plataforma=f"Python {plataforma.get('python', '?')}, "
                        f"{plataforma.get('sistema', '?')}"), e["nota"]),
    ]
    cols = ("escenario", "red", "media", "desviacion", "mediana", "min", "max", "bytes")
    filas = [_cabecera([t(f"apendice.col.{c}") for c in cols], e["mini_cab"])]
    for ag in f3["agregados"]:
        p = conf["perfiles"].get(ag["perfil"], {"nombre": ag["perfil"], "latencia_ms": 0})
        tm = ag["tiempo_ms"]
        filas.append([_p(x, e["mini"]) for x in (
            t(f"escenario.{ag['escenario']}") if t.existe(f"escenario.{ag['escenario']}")
            else ag["escenario"],
            _perfil(ag["perfil"], p["nombre"], p["latencia_ms"], t),
            t.numero(tm["media"]), t.numero(tm["desviacion"]), t.numero(tm["mediana"]),
            t.numero(tm["min"]), t.numero(tm["max"]), str(ag["bytes"]["total"]))])
    anchos = [2.4 * cm, 4.4 * cm] + [1.55 * cm] * 5
    anchos.append(ANCHO - sum(anchos))
    partes.append(_tabla(filas, anchos))
    return partes


# --- Documento ---------------------------------------------------------------------------
def construir_pdf(a: Analisis, t: Traductor, empresa: dict[str, str], salida: Path,
                  fecha: date) -> None:
    e = _estilos()

    def pie(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GRIS)
        canvas.drawCentredString(A4[0] / 2, 1.2 * cm,
                                 _seguro(t("pie", empresa=empresa["nombre"],
                                           pagina=doc.page)))
        canvas.restoreState()

    def portada(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(AZUL)
        canvas.rect(0, A4[1] - 1.1 * cm, A4[0], 1.1 * cm, stroke=0, fill=1)
        canvas.restoreState()
        canvas.showOutline()

    doc = SimpleDocTemplate(
        str(salida), pagesize=A4, leftMargin=MARGEN, rightMargin=MARGEN,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=_seguro(t("titulo")), author=_seguro(empresa["nombre"]),
        subject=_seguro(t("portada.subtitulo")), creator="Quantum Ready",
        lang=t.idioma)
    historia = (
        _portada(a, t, empresa, fecha, e)
        + _resumen(a, t, e)
        + _hallazgos(a, t, e)
        + _solucion(a, t, e)
        + _coste(a, t, e)
        + _pendiente(a, t, e)
        + _apendice(a, t, e)
    )
    doc.build(historia, onFirstPage=portada, onLaterPages=pie)

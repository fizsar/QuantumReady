import json
from datetime import date
from pathlib import Path

import pytest
from pypdf import PdfReader

from quantum_ready.escaner import escanear
from quantum_ready.informe.generador import (
    ErrorEntrada, FilaCoste, cargar_entradas, datos_empresa, encuadre_coste, familia,
    generar, main, reparto_solucion, riesgo_global, uso)
from quantum_ready.informe.traducciones import IDIOMAS, TEXTOS, Traductor, marcadores
from quantum_ready.inventario import cargar
from quantum_ready.tunel.hibrido import ejecutar_intercambio, resultados_json

RAIZ = Path(__file__).parent.parent
SECCIONES = ("portada", "resumen", "hallazgos", "solucion", "coste", "pendiente",
             "apendice")


def h(nivel=None, algoritmo_id="ECDH", directiva="KexAlgorithms", valor="x",
      formato="ssh", servicio="s"):
    """Hallazgo mínimo con la forma del informe.json de la Fase 1."""
    riesgo = {"nivel": nivel, "puntuacion": {"Urgente": 16, "Alto": 8, "Medio": 4,
                                             "Bajo": 2, "Ninguno": 0}[nivel]} if nivel else None
    return {"algoritmo_id": algoritmo_id, "algoritmo": algoritmo_id, "riesgo": riesgo,
            "directiva": directiva, "valor": valor, "formato": formato,
            "servicio": servicio}


# --- Riesgo global: regla del peor caso ---------------------------------------------
@pytest.mark.parametrize("niveles, esperado", [
    (["Urgente"], "Crítico"),
    (["Bajo", "Alto", "Medio"], "Alto"),                       # ningún Urgente, sí Alto
    (["Medio", "Bajo", "Medio"], "Medio"),
    (["Bajo", "Ninguno", "Bajo"], "Bajo"),                     # todos Bajo/Ninguno
    (["Ninguno", "Bajo", "Medio", "Alto", "Urgente"], "Crítico"),  # mezcla de todos
    ([], "Bajo"),                                               # ningún hallazgo
])
def test_riesgo_global(niveles, esperado):
    r = riesgo_global([h(n) for n in niveles])
    assert r.nivel == esperado
    assert r.total == len(niveles)


def test_riesgo_global_cuenta_por_nivel_e_ignora_los_no_evaluados():
    hallazgos = [h("Urgente"), h("Urgente"), h("Alto"), h(None), h(None)]
    r = riesgo_global(hallazgos)
    assert r.nivel == "Crítico"
    assert r.conteo == {"Urgente": 2, "Alto": 1}
    assert r.total == 5  # los no evaluados cuentan como elementos analizados


def test_un_solo_urgente_entre_muchos_bajos_es_critico():
    assert riesgo_global([h("Bajo")] * 50 + [h("Urgente")]).nivel == "Crítico"


# --- Qué resuelve la solución --------------------------------------------------------
@pytest.mark.parametrize("hallazgo, esperado", [
    (h(algoritmo_id="ECDH"), "intercambio"),
    (h(algoritmo_id="DH"), "intercambio"),
    (h(algoritmo_id="ECDSA", directiva="HostKey"), "firma"),          # Ed25519
    (h(algoritmo_id="DSA"), "firma"),
    (h(algoritmo_id="WG-SIN-PSK", directiva="[Peer]"), "intercambio"),
    (h(algoritmo_id="SHA-1"), "configuracion"),
    (h(algoritmo_id="AES-256-CBC"), "configuracion"),
])
def test_uso(hallazgo, esperado):
    assert uso(hallazgo) == esperado


@pytest.mark.parametrize("directiva, valor, formato, esperado", [
    # RSA como firma: claves de host, certificados, autenticación, suites con (EC)DHE
    ("HostKey", "/etc/ssh/ssh_host_rsa_key", "ssh", "firma"),
    ("HostKeyAlgorithms", "rsa-sha2-512", "ssh", "firma"),
    ("clave pública", "CN=web · RSA-2048", "certificado", "firma"),
    ("authby", "rsasig", "ipsec", "firma"),
    ("ssl_ciphers", "ECDHE-RSA-AES256-GCM-SHA384", "nginx", "firma"),
    ("SSLCipherSuite", "DHE-RSA-AES256-SHA", "apache", "firma"),
    # RSA como transporte de la clave de sesión: intercambio
    ("SSLCipherSuite", "TLS_RSA_WITH_AES_128_CBC_SHA", "apache", "intercambio"),
    ("ssl_ciphers", "AES256-SHA:RSA", "nginx", "intercambio"),
])
def test_rsa_segun_contexto(directiva, valor, formato, esperado):
    assert uso(h(algoritmo_id="RSA", directiva=directiva, valor=valor,
                 formato=formato)) == esperado


def test_reparto_con_rsa_ecdh_y_ed25519_mezclados():
    hallazgos = [
        h("Urgente", "RSA", "HostKey", "ssh_host_rsa_key"),               # firma
        h("Alto", "RSA", "SSLCipherSuite", "TLS_RSA_WITH_AES_128_CBC_SHA",
          "apache"),                                                      # intercambio
        h("Urgente", "ECDH", "KexAlgorithms", "ecdh-sha2-nistp256"),      # intercambio
        h("Alto", "ECDH", "ssl_ecdh_curve", "X25519", "nginx"),           # intercambio
        h("Urgente", "ECDSA", "HostKeyAlgorithms", "ssh-ed25519"),        # firma (Ed25519)
        h("Alto", "ECDSA", "HostKey", "ssh_host_ed25519_key"),            # firma (Ed25519)
        h("Urgente", "SHA-1", "MACs", "hmac-sha1"),                       # configuración
        h("Medio", "ECDH", "KexAlgorithms", "curve25519-sha256"),         # no prioritario
        h(None, "RSA", "HostKey", "x"),                                   # sin evaluar
    ]
    reparto = reparto_solucion(hallazgos)
    assert {k: len(v) for k, v in reparto.items()} == {
        "intercambio": 3, "firma": 3, "configuracion": 1}
    assert [x["valor"] for x in reparto["firma"]] == [
        "ssh_host_rsa_key", "ssh-ed25519", "ssh_host_ed25519_key"]


def test_familia_cbc_y_desconocidos():
    assert familia(h(algoritmo_id="3DES-CBC")) == "cbc"
    assert familia(h(algoritmo_id="ALGO-NUEVO")) == "otro"
    assert uso(h(algoritmo_id="ALGO-NUEVO")) == "configuracion"  # nunca "resuelto"


# --- Encuadre del coste: derivado de los datos ----------------------------------------
def _filas(*extras):
    return [FilaCoste(str(i), "p", 1, 10, 10 + e, e, e * 10) for i, e in enumerate(extras)]


@pytest.mark.parametrize("extras, clave", [
    ((0.5, 0.8, 0.9), "coste.encuadre.todos"),
    ((0.5, 0.8, 1.2), "coste.encuadre.mayoria"),
    ((0.92, 1.08, 0.90, 1.11), "coste.encuadre.aprox"),  # 2 de 4: no es mayoría
])
def test_encuadre_coste(extras, clave):
    t = Traductor("es")
    texto = encuadre_coste(_filas(*extras), t)
    plantilla = TEXTOS["es"][clave]
    assert texto.startswith(plantilla.split("{")[0])


def test_encuadre_aproximado_da_el_rango_real():
    texto = encuadre_coste(_filas(0.92, 1.08, 0.90, 1.11), Traductor("es"))
    assert "entre 0,90 y 1,11 ms" in texto


# --- Traducciones ---------------------------------------------------------------------
def test_mismas_claves_en_ambos_idiomas():
    assert set(TEXTOS["es"]) == set(TEXTOS["en"])


@pytest.mark.parametrize("clave", sorted(TEXTOS["es"]))
def test_mismos_marcadores_y_forma(clave):
    es, en = TEXTOS["es"][clave], TEXTOS["en"][clave]
    assert type(es) is type(en)
    assert marcadores(es) == marcadores(en)


def test_traductor():
    assert Traductor("es").plural("nivel.Urgente", 3) == "3 Urgentes"
    assert Traductor("es").plural("nivel.Urgente", 1) == "1 Urgente"
    assert Traductor("en").plural("nivel.Alto", 7) == "7 High"
    assert Traductor("es").numero(1.5) == "1,50"
    assert Traductor("en").numero(1.5) == "1.50"
    assert Traductor("es").fecha(26, 9, 2026) == "26 de septiembre de 2026"
    assert Traductor("en").fecha(26, 9, 2026) == "26 September 2026"
    with pytest.raises(ValueError):
        Traductor("fr")


# --- Datos de la empresa ----------------------------------------------------------------
def test_empresa_por_defecto_segun_idioma():
    assert datos_empresa("en")["sector"] == "Energy and utilities"
    assert datos_empresa("es")["sector"] == "Energía y servicios públicos"


def test_empresa_yaml_y_linea_de_comandos(tmp_path):
    ruta = tmp_path / "empresa.yaml"
    ruta.write_text("nombre: Real S.A.\nsector: {es: Banca, en: Banking}\n",
                    encoding="utf-8")
    empresa = datos_empresa("en", ruta, contacto="ciso@real.test")
    assert empresa == {"nombre": "Real S.A.", "sector": "Banking",
                       "contacto": "ciso@real.test"}
    assert datos_empresa("es", ruta, nombre="Otra")["nombre"] == "Otra"


# --- Entradas ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def entradas_reales(tmp_path_factory):
    """Las tres entradas generadas con el código real de las Fases 1 y 2."""
    carpeta = tmp_path_factory.mktemp("entradas")
    fase1 = carpeta / "informe.json"
    fase1.write_text(json.dumps(escanear([], cargar(RAIZ / "ejemplos/inventario.yaml"))),
                     encoding="utf-8")
    fase2 = carpeta / "resultados_intercambio.json"
    fase2.write_text(json.dumps(resultados_json(ejecutar_intercambio())), encoding="utf-8")
    return fase1, fase2, RAIZ / "resultados_overhead.referencia.json"


def test_entrada_inexistente_dice_como_generarla(tmp_path, entradas_reales):
    _, fase2, fase3 = entradas_reales
    with pytest.raises(ErrorEntrada, match="python -m quantum_ready"):
        cargar_entradas(tmp_path / "no.json", fase2, fase3)


def test_entrada_de_otra_fase(entradas_reales):
    fase1, fase2, fase3 = entradas_reales
    with pytest.raises(ErrorEntrada, match="Fase 2"):
        cargar_entradas(fase1, fase1, fase3)


def test_informe_de_version_anterior(tmp_path, entradas_reales):
    fase1, fase2, fase3 = entradas_reales
    datos = json.loads(fase1.read_text(encoding="utf-8"))
    for hallazgo in datos["hallazgos"]:
        del hallazgo["algoritmo_id"]
    viejo = tmp_path / "viejo.json"
    viejo.write_text(json.dumps(datos), encoding="utf-8")
    with pytest.raises(ErrorEntrada, match="algoritmo_id"):
        cargar_entradas(viejo, fase2, fase3)


# --- PDF ----------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def pdfs(entradas_reales, tmp_path_factory):
    carpeta = tmp_path_factory.mktemp("pdf")
    entradas = cargar_entradas(*entradas_reales)
    rutas = {}
    for idioma in IDIOMAS:
        rutas[idioma] = generar(entradas, idioma, carpeta / f"informe_{idioma}.pdf",
                                datos_empresa(idioma), date(2026, 9, 26))
    return rutas


@pytest.mark.parametrize("idioma", IDIOMAS)
def test_pdf_tiene_las_7_secciones(pdfs, idioma):
    lector = PdfReader(pdfs[idioma])
    titulos = [entrada.title for entrada in lector.outline]
    t = Traductor(idioma)
    assert titulos == [t(f"seccion.{s}") for s in SECCIONES]
    # Cada sección empieza en una página distinta y en orden
    paginas = [lector.get_destination_page_number(e) for e in lector.outline]
    assert paginas == sorted(paginas) and len(set(paginas)) == 7


@pytest.mark.parametrize("idioma", IDIOMAS)
def test_pdf_metadatos_e_idioma(pdfs, idioma):
    lector = PdfReader(pdfs[idioma])
    assert lector.metadata.title == Traductor(idioma)("titulo")
    assert lector.trailer["/Root"].get("/Lang") == idioma


def test_ambos_idiomas_igual_de_completos(pdfs):
    es, en = (PdfReader(pdfs[i]) for i in ("es", "en"))
    assert len(es.outline) == len(en.outline) == 7
    assert abs(len(es.pages) - len(en.pages)) <= 1


def test_pdf_en_ingles_sin_textos_en_castellano(pdfs):
    texto = "\n".join(p.extract_text() for p in PdfReader(pdfs["en"]).pages)
    for resto in ("Prioridad", "Qué ocurre", "Resumen ejecutivo", "Página",
                  "Hallazgos", "en modo CBC", "sin PresharedKey", "clave pública"):
        assert resto not in texto
    assert "Executive summary" in texto


def test_pdf_cuenta_la_verdad_sobre_el_coste(pdfs):
    texto = "\n".join(p.extract_text() for p in PdfReader(pdfs["es"]).pages)
    # Con los datos de referencia, 2 de 4 perfiles superan 1 ms: no se afirma
    # "menos de 1 ms en la mayoría".
    assert "en la mayoría" not in texto
    assert "ancho de banda no limitado" in texto


def test_cli(tmp_path, entradas_reales, capsys):
    fase1, fase2, fase3 = entradas_reales
    salida = tmp_path / "informe_en.pdf"
    assert main(["--idioma", "en", "--salida", str(salida), "--fase1", str(fase1),
                 "--fase2", str(fase2), "--fase3", str(fase3),
                 "--empresa-nombre", "Acme"]) == 0
    assert PdfReader(salida).metadata.author == "Acme"
    assert main(["--idioma", "en", "--fase1", str(tmp_path / "no.json")]) == 2
    assert "python -m quantum_ready" in capsys.readouterr().err


def test_cli_exige_idioma():
    with pytest.raises(SystemExit):
        main([])

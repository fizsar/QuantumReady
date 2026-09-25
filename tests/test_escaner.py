import json
from pathlib import Path

import pytest

from quantum_ready.cli import main
from quantum_ready.escaner import escanear
from quantum_ready.inventario import ErrorInventario, cargar

EJEMPLOS = Path(__file__).parent.parent / "ejemplos"


@pytest.fixture
def informe():
    return escanear([], cargar(EJEMPLOS / "inventario.yaml"))


def test_escanea_todas_las_rutas_del_inventario(informe):
    assert informe["resumen"]["archivos_escaneados"] == 7
    assert {s["nombre"]: s["archivos"] for s in informe["servicios"]} == {
        "bastion-ssh": 1, "vpn-sedes": 2, "web-publica": 3, "intranet": 1}


def test_campos_de_cada_hallazgo(informe):
    h = informe["hallazgos"][0]
    assert set(h) >= {"archivo", "linea", "algoritmo", "categoria", "riesgo",
                      "recomendacion"}
    assert h["riesgo"]["puntuacion"] == 16  # ordenados de mayor a menor riesgo


def test_riesgo_usa_exposicion_y_alcance_del_servicio(informe):
    def riesgo(servicio, algoritmo):
        return next(h["riesgo"] for h in informe["hallazgos"]
                    if h["servicio"] == servicio and h["algoritmo"] == algoritmo)

    assert riesgo("bastion-ssh", "ECDH / ECDHE")["puntuacion"] == 16   # 4×2×2
    assert riesgo("web-publica", "ECDH / ECDHE")["puntuacion"] == 8    # 4×2×1
    assert riesgo("intranet", "ECDH / ECDHE")["puntuacion"] == 4       # 4×1×1


def test_archivo_fuera_del_inventario_queda_sin_evaluar(tmp_path):
    (tmp_path / "sshd_config").write_text("Ciphers aes128-ctr\n")
    informe = escanear([tmp_path / "sshd_config"], None)
    assert informe["hallazgos"][0]["riesgo"] is None
    assert informe["resumen"]["sin_evaluar"] == 1


def test_rutas_explicitas_se_asocian_a_su_servicio():
    inventario = cargar(EJEMPLOS / "inventario.yaml")
    informe = escanear([EJEMPLOS / "vpn" / "wg0.conf"], inventario)
    assert {h["servicio"] for h in informe["hallazgos"]} == {"vpn-sedes"}


def test_inventario_invalido(tmp_path):
    ruta = tmp_path / "inventario.yaml"
    ruta.write_text("servicios:\n  - nombre: x\n    tipo: ssh\n    ruta: a\n"
                    "    exposicion: media\n    alcance: alto\n")
    with pytest.raises(ErrorInventario, match="exposicion"):
        cargar(ruta)


def test_cli_escribe_json(tmp_path, capsys):
    salida = tmp_path / "informe.json"
    assert main([str(EJEMPLOS / "bastion"), "-i", str(EJEMPLOS / "inventario.yaml"),
                 "-o", str(salida)]) == 0
    datos = json.loads(salida.read_text(encoding="utf-8"))
    assert datos["resumen"]["archivos_escaneados"] == 1
    assert "PRIORIDADES" in capsys.readouterr().out

import json
from pathlib import Path

import pytest

from quantum_ready import cumplimiento
from quantum_ready.cumplimiento import main, urgentes_principales
from quantum_ready.escaner import escanear
from quantum_ready.informe import generador
from quantum_ready.inventario import cargar

RAIZ = Path(__file__).parent.parent
PUNTOS = {"Urgente": 16, "Alto": 8, "Medio": 4, "Bajo": 2}


def h(nivel, puntuacion=None, linea=1):
    return {"riesgo": {"nivel": nivel, "puntuacion": puntuacion or PUNTOS[nivel]},
            "servicio": "s", "algoritmo": "RSA", "archivo": "a.conf", "linea": linea,
            "directiva": "d", "valor": "v"}


def escribir(tmp_path, hallazgos) -> Path:
    ruta = tmp_path / "informe.json"
    ruta.write_text(json.dumps({"hallazgos": hallazgos}), encoding="utf-8")
    return ruta


def test_usa_la_misma_funcion_que_la_fase_4():
    assert cumplimiento.riesgo_global is generador.riesgo_global


@pytest.mark.parametrize("niveles, codigo", [
    (["Urgente", "Bajo"], 1),          # Crítico → falla
    (["Alto", "Medio"], 0),            # Alto → pasa
    (["Medio"], 0),
    (["Bajo", "Bajo"], 0),
    ([], 0),                           # sin hallazgos → Bajo
])
def test_codigo_de_salida_segun_nivel_global(tmp_path, niveles, codigo, capsys):
    assert main([str(escribir(tmp_path, [h(n) for n in niveles]))]) == codigo
    salida = capsys.readouterr().out
    assert ("FALLO" in salida) == (codigo == 1)
    assert ("OK" in salida) == (codigo == 0)


def test_resumen_con_conteos(tmp_path, capsys):
    main([str(escribir(tmp_path, [h("Urgente"), h("Urgente"), h("Alto"), h("Bajo")]))])
    salida = capsys.readouterr().out
    assert "Nivel de riesgo global: Crítico" in salida
    assert "2 Urgentes, 1 Altos, 4 elementos analizados" in salida


def test_urgentes_principales_ordenados_y_limitados():
    hallazgos = [h("Urgente", 12, linea=i) for i in range(4)] + \
                [h("Urgente", 16, linea=10 + i) for i in range(3)] + [h("Alto")]
    principales = urgentes_principales(hallazgos)
    assert len(principales) == 5
    assert [x["riesgo"]["puntuacion"] for x in principales] == [16, 16, 16, 12, 12]


def test_anotacion_de_error_solo_en_github_actions(tmp_path, capsys, monkeypatch):
    ruta = escribir(tmp_path, [h("Urgente")])
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    main([str(ruta)])
    assert "::error" not in capsys.readouterr().out
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    main([str(ruta)])
    assert "::error title=Auditoría de cumplimiento::" in capsys.readouterr().out


def test_entrada_no_valida(tmp_path, capsys):
    assert main([str(tmp_path / "no_existe.json")]) == 2
    ruta = tmp_path / "otro.json"
    ruta.write_text('{"otra": "cosa"}', encoding="utf-8")
    assert main([str(ruta)]) == 2


def test_inventario_de_ejemplo_es_critico(tmp_path, capsys):
    """El inventario de ejemplo tiene Urgentes a propósito: el job de CI falla."""
    informe = escanear([], cargar(RAIZ / "ejemplos/inventario.yaml"))
    ruta = tmp_path / "informe.json"
    ruta.write_text(json.dumps(informe), encoding="utf-8")
    assert main([str(ruta)]) == 1
    assert "22 Urgentes, 14 Altos" in capsys.readouterr().out

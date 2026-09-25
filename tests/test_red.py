import json
import socket
import time

import pytest

from quantum_ready.red.benchmark import (Perfil, construir_informe, ejecutar_benchmark,
                                         main, overhead_vs_x25519, verificar_fase2)
from quantum_ready.red.cliente import ejecutar_handshake
from quantum_ready.red.escenarios import ESCENARIOS
from quantum_ready.red.servidor import ServidorHandshake
from quantum_ready.red.transporte import enviar, esperar, recibir

BYTES = {  # (Cliente → Servidor, Servidor → Cliente)
    "x25519": (32, 32),
    "mlkem768": (1184, 1088),
    "hibrido": (1216, 1120),
}
# Holgura para el planificador del sistema operativo al medir tiempos
TOLERANCIA_S = 0.015


# --- Latencia inyectada ---------------------------------------------------------------
@pytest.mark.parametrize("segundos", [0.002, 0.025])
def test_esperar_cumple_la_latencia(segundos):
    t = time.perf_counter()
    esperar(segundos)
    transcurrido = time.perf_counter() - t
    assert segundos <= transcurrido < segundos + TOLERANCIA_S


def test_enviar_aplica_la_latencia_antes_de_escribir():
    a, b = socket.socketpair()
    with a, b:
        t = time.perf_counter()
        assert enviar(a, b"hola", 0.05) == 4
        assert recibir(b) == b"hola"
        transcurrido = time.perf_counter() - t
    assert 0.05 <= transcurrido < 0.05 + TOLERANCIA_S


def test_handshake_paga_la_latencia_en_cada_tramo():
    latencia = 0.04
    with ServidorHandshake("x25519", latencia) as servidor:
        # El primer handshake de un proceso recién arrancado es 25-60 ms más
        # lento (arranque en frío); el benchmark lo descarta con el calentamiento.
        ejecutar_handshake(servidor.direccion, ESCENARIOS["x25519"], latencia)
        servidor.siguiente_resultado()
        t = time.perf_counter()
        cliente = ejecutar_handshake(servidor.direccion, ESCENARIOS["x25519"], latencia)
        transcurrido = time.perf_counter() - t
        servidor.siguiente_resultado()
    duracion = cliente.t_clave - cliente.t_inicio
    assert 2 * latencia <= duracion <= transcurrido < 2 * latencia + TOLERANCIA_S


def test_recibir_detecta_conexion_cortada():
    a, b = socket.socketpair()
    with b:
        a.sendall(b"\x00\x00\x00\x10abc")  # anuncia 16 bytes y envía 3
        a.close()
        with pytest.raises(ConnectionError):
            recibir(b)


def test_recibir_rechaza_longitudes_absurdas():
    a, b = socket.socketpair()
    with a, b:
        a.sendall(b"\xff\xff\xff\xff")
        with pytest.raises(ValueError):
            recibir(b)


# --- Los tres escenarios producen secretos compartidos válidos ------------------------
@pytest.mark.parametrize("escenario_id", list(ESCENARIOS))
def test_escenario_en_memoria(escenario_id):
    e = ESCENARIOS[escenario_id]
    estado, mensaje = e.iniciar()
    respuesta, clave_servidor = e.responder(mensaje)
    clave_cliente = e.finalizar(estado, respuesta)
    assert clave_cliente == clave_servidor and len(clave_cliente) == 32
    assert (len(mensaje), len(respuesta)) == BYTES[escenario_id]


@pytest.mark.parametrize("escenario_id", list(ESCENARIOS))
def test_escenario_sobre_tcp(escenario_id):
    with ServidorHandshake(escenario_id, 0) as servidor:
        for _ in range(3):
            cliente = ejecutar_handshake(servidor.direccion, ESCENARIOS[escenario_id], 0)
            lado_servidor = servidor.siguiente_resultado()
            assert cliente.clave == lado_servidor.clave
            assert (cliente.bytes_enviados, cliente.bytes_recibidos) == BYTES[escenario_id]
            assert lado_servidor.bytes_recibidos == BYTES[escenario_id][0]


def test_cada_handshake_da_una_clave_nueva():
    with ServidorHandshake("hibrido", 0) as servidor:
        claves = set()
        for _ in range(3):
            claves.add(ejecutar_handshake(servidor.direccion, ESCENARIOS["hibrido"], 0).clave)
            servidor.siguiente_resultado()
    assert len(claves) == 3


def test_mensaje_hibrido_malformado_da_error_en_el_servidor():
    with ServidorHandshake("hibrido", 0) as servidor:
        with socket.create_connection(servidor.direccion) as s:
            enviar(s, b"\x00" * 100, 0)
        with pytest.raises(RuntimeError, match="key_share del Cliente"):
            servidor.siguiente_resultado()


# --- Estructura del JSON ----------------------------------------------------------------
@pytest.fixture(scope="module")
def informe(tmp_path_factory):
    perfiles = [Perfil("prueba", "Prueba", 1), Perfil("otra", "Otra", 3)]
    escenarios = list(ESCENARIOS.values())
    ejecuciones = ejecutar_benchmark(3, perfiles, escenarios, calentamiento=1)
    fase2 = tmp_path_factory.mktemp("fase2") / "resultados_intercambio.json"
    fase2.write_text(json.dumps({"bytes_en_red": {
        "cliente_a_servidor": 1216, "servidor_a_cliente": 1120, "total": 2336}}))
    datos = construir_informe(ejecuciones, perfiles, escenarios, 3, 1, fase2)
    return json.loads(json.dumps(datos))  # lo que realmente se escribe en disco


def test_json_estructura_general(informe):
    assert set(informe) == {"fase", "generado", "configuracion", "agregados",
                            "overhead_hibrido_vs_x25519", "verificacion_fase2",
                            "ejecuciones"}
    assert informe["fase"] == 3
    assert informe["configuracion"]["repeticiones"] == 3
    assert set(informe["configuracion"]["perfiles"]) == {"prueba", "otra"}


def test_json_ejecuciones_crudas(informe):
    assert len(informe["ejecuciones"]) == 3 * 3 * 2
    fila = informe["ejecuciones"][0]
    assert set(fila) == {"escenario", "perfil", "iteracion", "tiempo_ms",
                         "bytes_cliente_a_servidor", "bytes_servidor_a_cliente",
                         "claves_coinciden"}
    assert all(f["claves_coinciden"] for f in informe["ejecuciones"])


def test_json_agregados(informe):
    assert len(informe["agregados"]) == 6
    for a in informe["agregados"]:
        assert a["n"] == 3 and a["claves_coinciden"] == 3
        assert set(a["tiempo_ms"]) == {"media", "desviacion", "mediana", "min", "max"}
        assert a["tiempo_ms"]["min"] >= a["latencia_inyectada_ms"]
        assert (a["bytes"]["cliente_a_servidor"],
                a["bytes"]["servidor_a_cliente"]) == BYTES[a["escenario"]]


def test_json_overhead_por_perfil(informe):
    overhead = informe["overhead_hibrido_vs_x25519"]
    assert set(overhead) == {"prueba", "otra"}
    for o in overhead.values():
        assert set(o) == {"bytes_pct", "bytes_extra", "tiempo_pct", "tiempo_extra_ms"}
        assert o["bytes_pct"] == pytest.approx((2336 - 64) / 64 * 100)
        assert o["bytes_extra"] == 2272


def test_json_verificacion_fase2(informe):
    assert informe["verificacion_fase2"]["coincide"] is True


def test_overhead_calculo():
    def agregado(escenario, media, total):
        return {"escenario": escenario, "perfil": "p", "tiempo_ms": {"media": media},
                "bytes": {"total": total}}
    o = overhead_vs_x25519([agregado("x25519", 100.0, 64), agregado("hibrido", 110.0, 2336)])
    assert o == {"p": {"bytes_pct": 3550.0, "bytes_extra": 2272,
                       "tiempo_pct": pytest.approx(10.0), "tiempo_extra_ms": 10.0}}


def test_verificar_fase2_sin_archivo(tmp_path):
    assert verificar_fase2([], tmp_path / "no_existe.json")["encontrado"] is False


def test_verificar_fase2_detecta_diferencias(tmp_path):
    ruta = tmp_path / "f2.json"
    ruta.write_text(json.dumps({"bytes_en_red": {
        "cliente_a_servidor": 1, "servidor_a_cliente": 2, "total": 3}}))
    agregados = [{"escenario": "hibrido", "bytes": {
        "cliente_a_servidor": 1216, "servidor_a_cliente": 1120, "total": 2336}}]
    assert verificar_fase2(agregados, ruta)["coincide"] is False


def test_cli(tmp_path, capsys):
    salida = tmp_path / "resultados_overhead.json"
    assert main(["-n", "2", "--perfiles", "fibra", "--calentamiento", "0",
                 "-o", str(salida), "--fase2", str(tmp_path / "no.json")]) == 0
    datos = json.loads(salida.read_text(encoding="utf-8"))
    assert len(datos["ejecuciones"]) == 6
    texto = capsys.readouterr().out
    assert "OVERHEAD DEL HÍBRIDO FRENTE A X25519 PURO" in texto
    assert "✅ Cliente y Servidor obtienen la misma clave en los 6 handshakes" in texto

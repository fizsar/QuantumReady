import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from quantum_ready.tunel.actores import Atacante, Cliente, Servidor
from quantum_ready.tunel.cripto import (INFO_HKDF, combinar_secretos,
                                        derivar_clave_final)
from quantum_ready.tunel.hibrido import ejecutar_intercambio, main, resultados_json


def _otra_x25519() -> bytes:
    return x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()


def _otra_mlkem() -> bytes:
    return mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw()


def _voltear_bit(datos: bytes) -> bytes:
    return bytes([datos[0] ^ 1]) + datos[1:]


# (a) Cliente y Servidor coinciden --------------------------------------------------
def test_cliente_y_servidor_obtienen_la_misma_clave():
    r = ejecutar_intercambio()
    assert r.coinciden
    assert r.clave_cliente == r.clave_servidor
    assert len(r.clave_cliente) == 32


def test_cada_intercambio_produce_una_clave_distinta():
    assert ejecutar_intercambio().clave_servidor != ejecutar_intercambio().clave_servidor


# (b) El Atacante no coincide -------------------------------------------------------
def test_el_atacante_no_obtiene_la_clave():
    r = ejecutar_intercambio()
    assert not r.atacante_coincide
    assert all(i.clave != r.clave_servidor for i in r.intentos_atacante)


def test_el_atacante_solo_ve_datos_publicos():
    servidor, cliente = Servidor(), Cliente()
    publicas = servidor.claves_publicas()
    respuesta = cliente.responder(publicas)
    atacante = Atacante()
    atacante.observar(publicas, respuesta)
    # Lo observado no contiene ningún secreto ni clave privada
    observado = (publicas.x25519 + publicas.mlkem768 + respuesta.x25519
                 + respuesta.mlkem768_ciphertext)
    for secreto in (cliente.secreto_x25519, cliente.secreto_mlkem,
                    servidor._x25519.private_bytes_raw(),
                    servidor._mlkem.private_bytes_raw()):
        assert secreto not in observado


# (c) Cambiar una sola clave rompe la coincidencia ----------------------------------
@pytest.mark.parametrize("manipular_servidor, manipular_cliente", [
    (lambda m: replace(m, x25519=_otra_x25519()), None),
    (lambda m: replace(m, mlkem768=_otra_mlkem()), None),
    (None, lambda m: replace(m, x25519=_otra_x25519())),
    (None, lambda m: replace(m, mlkem768_ciphertext=_voltear_bit(m.mlkem768_ciphertext))),
], ids=["x25519-servidor", "mlkem-servidor", "x25519-cliente", "ciphertext-1-bit"])
def test_cambiar_un_elemento_rompe_la_coincidencia(manipular_servidor, manipular_cliente):
    servidor, cliente = Servidor(), Cliente()
    publicas = servidor.claves_publicas()
    if manipular_servidor:
        publicas = manipular_servidor(publicas)
    respuesta = cliente.responder(publicas)
    if manipular_cliente:
        respuesta = manipular_cliente(respuesta)
    servidor.recibir(respuesta)
    assert cliente.derivar() != servidor.derivar()


@pytest.mark.parametrize("cual", ["secreto_mlkem", "secreto_x25519"])
def test_cambiar_un_byte_de_cualquier_secreto_cambia_la_clave(cual):
    secretos = {"secreto_mlkem": bytes(32), "secreto_x25519": bytes(range(32))}
    base = derivar_clave_final(**secretos)
    secretos[cual] = _voltear_bit(secretos[cual])
    assert derivar_clave_final(**secretos) != base


# Orden de concatenación: ML-KEM || X25519, como X25519MLKEM768 (TLS 1.3) --------
MLKEM, X = b"" * 32, b"" * 32


def _hkdf_de_referencia(entrada: bytes) -> bytes:
    """HKDF-SHA384 calculado aparte, sin pasar por el código bajo prueba."""
    return HKDF(algorithm=hashes.SHA384(), length=32, salt=None,
                info=INFO_HKDF).derive(entrada)


def test_combinar_pone_mlkem_primero():
    combinado = combinar_secretos(secreto_mlkem=MLKEM, secreto_x25519=X)
    assert combinado == MLKEM + X
    assert combinado[:32] == MLKEM and combinado[32:] == X


def test_clave_final_es_hkdf_sobre_mlkem_y_despues_x25519():
    clave = derivar_clave_final(secreto_mlkem=MLKEM, secreto_x25519=X)
    assert clave == _hkdf_de_referencia(MLKEM + X)
    assert clave != _hkdf_de_referencia(X + MLKEM)


def test_los_secretos_solo_se_pasan_por_nombre():
    with pytest.raises(TypeError):
        derivar_clave_final(MLKEM, X)
    with pytest.raises(TypeError):
        combinar_secretos(MLKEM, X)


def test_cliente_y_servidor_usan_el_orden_estandar():
    """Extremo a extremo: la clave de ambos actores es HKDF(ML-KEM || X25519)."""
    servidor, cliente = Servidor(), Cliente()
    servidor.recibir(cliente.responder(servidor.claves_publicas()))
    for actor in (cliente, servidor):
        clave = actor.derivar()
        assert clave == _hkdf_de_referencia(actor.secreto_mlkem + actor.secreto_x25519)
        assert clave != _hkdf_de_referencia(actor.secreto_x25519 + actor.secreto_mlkem)


# Salida JSON para la Fase 3 -----------------------------------------------------------
def test_tamanos_json():
    datos = resultados_json(ejecutar_intercambio())
    assert datos["tamanos_bytes"] == {
        "x25519_clave_publica": 32,
        "mlkem768_clave_publica": 1184,
        "mlkem768_ciphertext": 1088,
        "clave_final": 32,
    }
    assert datos["bytes_en_red"]["total"] == 32 + 1184 + 32 + 1088
    assert datos["verificacion"] == {"cliente_servidor_coinciden": True,
                                     "atacante_coincide": False}


def test_main_escribe_el_json(tmp_path, capsys):
    salida = tmp_path / "resultados_intercambio.json"
    assert main(["-o", str(salida)]) == 0
    assert json.loads(salida.read_text(encoding="utf-8"))["fase"] == 2
    texto = capsys.readouterr().out
    assert "✅ Cliente y Servidor obtienen la misma clave" in texto
    assert "✅ El Atacante NO obtiene la clave" in texto

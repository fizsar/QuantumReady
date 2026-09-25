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


def _intercambio(manipular_cliente=None, manipular_servidor=None):
    """Cliente → Servidor → Cliente, con manipulación opcional de cada mensaje."""
    cliente, servidor = Cliente(), Servidor()
    publicas = cliente.claves_publicas()
    if manipular_cliente:
        publicas = manipular_cliente(publicas)
    respuesta = servidor.responder(publicas)
    if manipular_servidor:
        respuesta = manipular_servidor(respuesta)
    cliente.recibir(respuesta)
    return cliente, servidor, publicas, respuesta


# (a) Cliente y Servidor coinciden --------------------------------------------------
def test_cliente_y_servidor_obtienen_la_misma_clave():
    r = ejecutar_intercambio()
    assert r.coinciden
    assert r.clave_cliente == r.clave_servidor
    assert len(r.clave_cliente) == 32


def test_cada_intercambio_produce_una_clave_distinta():
    assert ejecutar_intercambio().clave_servidor != ejecutar_intercambio().clave_servidor


# Papeles de X25519MLKEM768: el Cliente genera ML-KEM, el Servidor encapsula --------
def test_solo_el_cliente_tiene_par_ml_kem():
    cliente, servidor, publicas, respuesta = _intercambio()
    assert isinstance(cliente._mlkem, mlkem.MLKEM768PrivateKey)
    assert not hasattr(servidor, "_mlkem")
    assert publicas.mlkem768 == cliente._mlkem.public_key().public_bytes_raw()


def test_el_servidor_encapsula_y_el_cliente_decapsula():
    cliente, servidor, _, respuesta = _intercambio()
    assert cliente._mlkem.decapsulate(respuesta.mlkem768_ciphertext) == servidor.secreto_mlkem
    elementos = [(e.actor, e.elemento) for e in cliente.registro + servidor.registro]
    assert ("Servidor", "Secreto ML-KEM (encapsulado)") in elementos
    assert ("Cliente", "Secreto ML-KEM (decapsulado)") in elementos


def test_key_shares_en_orden_estandar():
    _, _, publicas, respuesta = _intercambio()
    assert publicas.key_share == publicas.mlkem768 + publicas.x25519
    assert respuesta.key_share == respuesta.mlkem768_ciphertext + respuesta.x25519
    assert (len(publicas.key_share), len(respuesta.key_share)) == (1216, 1120)


# (b) El Atacante no coincide -------------------------------------------------------
def test_el_atacante_no_obtiene_la_clave():
    r = ejecutar_intercambio()
    assert not r.atacante_coincide
    assert all(i.clave != r.clave_servidor for i in r.intentos_atacante)


def test_el_atacante_solo_ve_datos_publicos():
    cliente, servidor, publicas, respuesta = _intercambio()
    atacante = Atacante()
    atacante.observar(publicas, respuesta)
    # Lo observado no contiene ningún secreto ni clave privada
    observado = publicas.key_share + respuesta.key_share
    for secreto in (servidor.secreto_x25519, servidor.secreto_mlkem,
                    cliente._x25519.private_bytes_raw(),
                    cliente._mlkem.private_bytes_raw()):
        assert secreto not in observado


# (c) Cambiar una sola clave rompe la coincidencia ----------------------------------
@pytest.mark.parametrize("manipular_cliente, manipular_servidor", [
    (lambda m: replace(m, mlkem768=_otra_mlkem()), None),
    (lambda m: replace(m, x25519=_otra_x25519()), None),
    (None, lambda m: replace(m, mlkem768_ciphertext=_voltear_bit(m.mlkem768_ciphertext))),
    (None, lambda m: replace(m, x25519=_otra_x25519())),
], ids=["mlkem-cliente", "x25519-cliente", "ciphertext-1-bit", "x25519-servidor"])
def test_cambiar_un_elemento_rompe_la_coincidencia(manipular_cliente, manipular_servidor):
    cliente, servidor, _, _ = _intercambio(manipular_cliente, manipular_servidor)
    assert cliente.derivar() != servidor.derivar()


@pytest.mark.parametrize("cual", ["secreto_mlkem", "secreto_x25519"])
def test_cambiar_un_byte_de_cualquier_secreto_cambia_la_clave(cual):
    secretos = {"secreto_mlkem": bytes(32), "secreto_x25519": bytes(range(32))}
    base = derivar_clave_final(**secretos)
    secretos[cual] = _voltear_bit(secretos[cual])
    assert derivar_clave_final(**secretos) != base


# Orden de concatenación: ML-KEM || X25519, como X25519MLKEM768 (TLS 1.3) --------
MLKEM, X = b"\x01" * 32, b"\x02" * 32


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
    cliente, servidor, _, _ = _intercambio()
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
    assert datos["verificacion"] == {"cliente_servidor_coinciden": True,
                                     "atacante_coincide": False}


def test_bytes_en_red_por_direccion_real():
    red = resultados_json(ejecutar_intercambio())["bytes_en_red"]
    assert red == {
        "cliente_a_servidor": 1184 + 32,   # pública ML-KEM + pública X25519
        "servidor_a_cliente": 1088 + 32,   # ciphertext + pública X25519
        "total": 2336,
    }


def test_main_escribe_el_json(tmp_path, capsys):
    salida = tmp_path / "resultados_intercambio.json"
    assert main(["-o", str(salida)]) == 0
    assert json.loads(salida.read_text(encoding="utf-8"))["fase"] == 2
    texto = capsys.readouterr().out
    assert "✅ Cliente y Servidor obtienen la misma clave" in texto
    assert "✅ El Atacante NO obtiene la clave" in texto

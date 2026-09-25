"""Los tres escenarios de intercambio de claves que se comparan.

Cada escenario se reduce a tres pasos, con los mismos papeles que TLS 1.3:

- ``iniciar()``        Cliente: genera claves → (estado, mensaje Cliente → Servidor)
- ``responder(msg)``   Servidor: → (mensaje Servidor → Cliente, clave final)
- ``finalizar(e, msg)`` Cliente: → clave final

Todos derivan una clave de 32 bytes con HKDF-SHA384, cada uno con su propio
``info`` para que un escenario nunca pueda producir la clave de otro.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..tunel.actores import Cliente, ClavesPublicasCliente, RespuestaServidor, Servidor
from ..tunel.cripto import LONGITUD_CLAVE_FINAL


@dataclass(frozen=True)
class Escenario:
    id: str
    nombre: str
    iniciar: Callable[[], tuple[Any, bytes]]
    responder: Callable[[bytes], tuple[bytes, bytes]]
    finalizar: Callable[[Any, bytes], bytes]


def _hkdf(secreto: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA384(), length=LONGITUD_CLAVE_FINAL,
                salt=None, info=info).derive(secreto)


# --- X25519 puro (clásico) -------------------------------------------------------
_INFO_X25519 = b"quantum-ready/fase3/x25519"


def _x25519_iniciar():
    privada = x25519.X25519PrivateKey.generate()
    return privada, privada.public_key().public_bytes_raw()


def _x25519_responder(mensaje: bytes):
    privada = x25519.X25519PrivateKey.generate()
    secreto = privada.exchange(x25519.X25519PublicKey.from_public_bytes(mensaje))
    return privada.public_key().public_bytes_raw(), _hkdf(secreto, _INFO_X25519)


def _x25519_finalizar(privada: x25519.X25519PrivateKey, respuesta: bytes):
    secreto = privada.exchange(x25519.X25519PublicKey.from_public_bytes(respuesta))
    return _hkdf(secreto, _INFO_X25519)


# --- ML-KEM-768 puro (post-cuántico) ---------------------------------------------
_INFO_MLKEM = b"quantum-ready/fase3/mlkem768"


def _mlkem_iniciar():
    privada = mlkem.MLKEM768PrivateKey.generate()
    return privada, privada.public_key().public_bytes_raw()


def _mlkem_responder(mensaje: bytes):
    secreto, ciphertext = mlkem.MLKEM768PublicKey.from_public_bytes(mensaje).encapsulate()
    return ciphertext, _hkdf(secreto, _INFO_MLKEM)


def _mlkem_finalizar(privada: mlkem.MLKEM768PrivateKey, respuesta: bytes):
    return _hkdf(privada.decapsulate(respuesta), _INFO_MLKEM)


# --- Híbrido: exactamente los actores de la Fase 2 --------------------------------
def _hibrido_iniciar():
    cliente = Cliente()
    return cliente, cliente.claves_publicas().key_share


def _hibrido_responder(mensaje: bytes):
    servidor = Servidor()
    respuesta = servidor.responder(ClavesPublicasCliente.desde_key_share(mensaje))
    return respuesta.key_share, servidor.derivar()


def _hibrido_finalizar(cliente: Cliente, respuesta: bytes):
    cliente.recibir(RespuestaServidor.desde_key_share(respuesta))
    return cliente.derivar()


ESCENARIOS: dict[str, Escenario] = {
    e.id: e for e in [
        Escenario("x25519", "X25519", _x25519_iniciar, _x25519_responder,
                  _x25519_finalizar),
        Escenario("mlkem768", "ML-KEM-768", _mlkem_iniciar, _mlkem_responder,
                  _mlkem_finalizar),
        Escenario("hibrido", "Híbrido ML-KEM-768 + X25519", _hibrido_iniciar,
                  _hibrido_responder, _hibrido_finalizar),
    ]
}

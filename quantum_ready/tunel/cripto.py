"""Primitivas del intercambio híbrido: combinación de secretos y derivación."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ESQUEMA = "ML-KEM-768 + X25519, HKDF-SHA384"
LONGITUD_CLAVE_FINAL = 32  # bytes: una clave AES-256
# Separación de dominio: la misma entrada con otro 'info' da otra clave
INFO_HKDF = b"quantum-ready/fase2/mlkem768-x25519"


def combinar_secretos(*, secreto_mlkem: bytes, secreto_x25519: bytes) -> bytes:
    """secreto_ML-KEM || secreto_X25519.

    Mismo orden que el estándar X25519MLKEM768 (TLS 1.3) y
    mlkem768x25519-sha256 (OpenSSH): ML-KEM primero. Los argumentos son solo
    por nombre para que ningún llamante pueda invertir el orden por error.
    """
    return secreto_mlkem + secreto_x25519


def derivar_clave_final(*, secreto_mlkem: bytes, secreto_x25519: bytes) -> bytes:
    """HKDF-SHA384 sobre secreto_ML-KEM || secreto_X25519.

    Mientras uno de los dos secretos siga siendo secreto, la clave final lo es:
    romper X25519 con Shor no basta, también habría que romper ML-KEM.
    """
    hkdf = HKDF(algorithm=hashes.SHA384(), length=LONGITUD_CLAVE_FINAL,
                salt=None, info=INFO_HKDF)
    return hkdf.derive(combinar_secretos(secreto_mlkem=secreto_mlkem,
                                         secreto_x25519=secreto_x25519))

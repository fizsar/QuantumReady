"""Certificado autofirmado para el gateway, generado con ``cryptography``.

Uso: python3 -m quantum_ready.gateway.certificado   (lo crea si no existe)

La firma del certificado es clásica (ECDSA P-256): el gateway protege el
intercambio de claves con X25519MLKEM768, no la autenticación del servidor.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .conf_openssl import directorio_trabajo

VALIDEZ = datetime.timedelta(days=30)


def rutas(directorio: Path) -> tuple[Path, Path]:
    return directorio / "gateway-cert.pem", directorio / "gateway-clave.pem"


def asegurar(directorio: Path) -> tuple[Path, Path]:
    """Devuelve (certificado, clave), creándolos si falta alguno o ha caducado."""
    cert, clave = rutas(directorio)
    if cert.exists() and clave.exists():
        existente = x509.load_pem_x509_certificate(cert.read_bytes())
        if existente.not_valid_after_utc > datetime.datetime.now(datetime.UTC):
            return cert, clave
    directorio.mkdir(parents=True, exist_ok=True)
    privada = ec.generate_private_key(ec.SECP256R1())
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    ahora = datetime.datetime.now(datetime.UTC)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(nombre).issuer_name(nombre)
        .public_key(privada.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - datetime.timedelta(minutes=5))
        .not_valid_after(ahora + VALIDEZ)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(privada, hashes.SHA256())
    )
    # La clave privada, solo legible por el usuario
    descriptor = os.open(clave, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as f:
        f.write(privada.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    cert.write_bytes(certificado.public_bytes(serialization.Encoding.PEM))
    return cert, clave


def main() -> int:
    cert, clave = asegurar(directorio_trabajo())
    print(f"Certificado: {cert}\nClave:       {clave}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Certificados X.509 (.pem, .crt, .cer, .der) y cabeceras de claves PEM."""

from __future__ import annotations

import re
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from ..reglas import ALGORITMOS, clasificar
from .base import ResultadoArchivo

_BLOQUE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)

# Claves privadas cuyo tipo se ve en la cabecera (no se leen las claves)
_CABECERAS_CLAVE = {
    "RSA PRIVATE KEY": "RSA",
    "EC PRIVATE KEY": "ECDSA",
    "DSA PRIVATE KEY": "DSA",
}

# OIDs post-cuánticos (NIST) que cryptography puede no saber interpretar
_OIDS_PQ = {
    **{f"2.16.840.1.101.3.4.3.{i}": f"ml-dsa-{n}"
       for i, n in ((17, 44), (18, 65), (19, 87))},
    **{f"2.16.840.1.101.3.4.3.{i}": "slh-dsa" for i in range(20, 32)},
    **{f"2.16.840.1.101.3.4.4.{i}": f"ml-kem-{n}"
       for i, n in ((1, 512), (2, 768), (3, 1024))},
}
_HASHES = {"MD5", "SHA-1", "SHA-256", "SHA-384/512"}


def _sujeto(cert: x509.Certificate) -> str:
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return f"CN={cn[0].value}" if cn else cert.subject.rfc4514_string() or "(sin sujeto)"


def _describir_clave(clave) -> tuple[str, str]:
    """(descripción legible, nombre a clasificar)."""
    if isinstance(clave, rsa.RSAPublicKey):
        return f"RSA-{clave.key_size}", "rsa"
    if isinstance(clave, ec.EllipticCurvePublicKey):
        return f"ECDSA {clave.curve.name}", "ecdsa"
    if isinstance(clave, ed25519.Ed25519PublicKey):
        return "Ed25519", "ed25519"
    if isinstance(clave, ed448.Ed448PublicKey):
        return "Ed448", "ed448"
    if isinstance(clave, dsa.DSAPublicKey):
        return f"DSA-{clave.key_size}", "dsa"
    return type(clave).__name__, ""


def _analizar_certificado(res: ResultadoArchivo, linea: int,
                          cert: x509.Certificate) -> None:
    sujeto = _sujeto(cert)

    # Clave pública del certificado
    try:
        descripcion, nombre = _describir_clave(cert.public_key())
    except (UnsupportedAlgorithm, ValueError):
        oid = cert.public_key_algorithm_oid.dotted_string
        descripcion, nombre = f"OID {oid}", _OIDS_PQ.get(oid, "")
    res.anadir(linea, "clave pública", f"{sujeto} · {descripcion}",
               clasificar_como=nombre or descripcion)

    # Firma del emisor: algoritmo de firma + hash
    oid = cert.signature_algorithm_oid
    nombre_firma = _OIDS_PQ.get(oid.dotted_string) or getattr(oid, "_name", oid.dotted_string)
    algoritmos = clasificar(nombre_firma)
    if not any(a.id in _HASHES for a in algoritmos):
        try:
            hash_ = cert.signature_hash_algorithm
        except UnsupportedAlgorithm:
            hash_ = None
        if hash_ is not None:
            algoritmos += clasificar(hash_.name)
    valor = f"{sujeto} · {nombre_firma}"
    if not algoritmos:
        res.anadir(linea, "firma", valor)  # queda como no reconocido
    for algoritmo in algoritmos:
        res.anadir_algoritmo(linea, "firma", valor, algoritmo)


def analizar(ruta: Path, datos: bytes) -> ResultadoArchivo:
    res = ResultadoArchivo(ruta, "certificado")
    if b"-----BEGIN" not in datos:
        try:
            _analizar_certificado(res, 1, x509.load_der_x509_certificate(datos))
        except ValueError:
            res.avisar("No es un certificado PEM ni DER legible.")
        return res

    for m in _BLOQUE.finditer(datos):
        linea = datos.count(b"\n", 0, m.start()) + 1
        tipo = m.group(1).decode()
        if tipo == "CERTIFICATE":
            try:
                cert = x509.load_pem_x509_certificate(m.group(0))
            except ValueError as e:
                res.avisar(f"Certificado ilegible: {e}", linea)
                continue
            _analizar_certificado(res, linea, cert)
        elif tipo in _CABECERAS_CLAVE:
            res.anadir_algoritmo(linea, "clave privada", tipo,
                                 ALGORITMOS[_CABECERAS_CLAVE[tipo]])
        else:
            res.avisar(f"Bloque '{tipo}' no analizado en la v1.", linea)
    return res

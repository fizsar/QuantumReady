"""Detección de formato y despacho al analizador correspondiente."""

from __future__ import annotations

import re
from pathlib import Path

from . import certificado, ssh, tls, vpn
from .base import Deteccion, NoReconocido, ResultadoArchivo

__all__ = ["Deteccion", "NoReconocido", "ResultadoArchivo", "detectar_formato",
           "analizar_archivo"]

EXTENSIONES_CERT = {".pem", ".crt", ".cer", ".der"}

ANALIZADORES = {
    "ssh": ssh.analizar,
    "nginx": tls.analizar_nginx,
    "apache": tls.analizar_apache,
    "ipsec": vpn.analizar_ipsec,
    "wireguard": vpn.analizar_wireguard,
}

_M = re.MULTILINE | re.IGNORECASE
_PISTAS = [
    ("apache", re.compile(r"^\s*(SSLProtocol|SSLCipherSuite|SSLEngine)\b", _M)),
    ("nginx", re.compile(r"^\s*(ssl_protocols|ssl_ciphers|ssl_certificate|server\s*\{|http\s*\{)", _M)),
    ("ssh", re.compile(r"^\s*(KexAlgorithms|Ciphers|MACs|HostKey|HostKeyAlgorithms|PermitRootLogin)\b", _M)),
    ("wireguard", re.compile(r"^\s*\[Interface\]", _M)),
    ("ipsec", re.compile(r"^\s*(conn\s+\S+|connections\s*\{)", _M)),
]


def detectar_formato(ruta: Path, texto: str | None = None) -> str | None:
    """Por nombre de archivo primero; si no basta, por contenido."""
    nombre = ruta.name.lower()
    if ruta.suffix.lower() in EXTENSIONES_CERT:
        return "certificado"
    if nombre.startswith(("sshd_config", "ssh_config")) or ruta.parent.name in (
            "sshd_config.d", "ssh_config.d"):
        return "ssh"
    if nombre in ("ipsec.conf", "swanctl.conf"):
        return "ipsec"
    if re.fullmatch(r"wg\w*\.conf", nombre):
        return "wireguard"
    if nombre in ("apache2.conf", "httpd.conf", "ssl.conf", "httpd-ssl.conf"):
        return "apache"
    if nombre == "nginx.conf":
        return "nginx"
    if texto is None:
        return None
    if "-----BEGIN CERTIFICATE-----" in texto:
        return "certificado"
    for formato, pista in _PISTAS:
        if pista.search(texto):
            return formato
    return None


def analizar_archivo(ruta: Path) -> ResultadoArchivo | None:
    """Analiza un archivo; None si no es un formato reconocido."""
    datos = ruta.read_bytes()
    texto = datos.decode("utf-8", errors="replace")
    formato = detectar_formato(ruta, texto)
    if formato is None:
        return None
    if formato == "certificado":
        return certificado.analizar(ruta, datos)
    return ANALIZADORES[formato](ruta, texto)

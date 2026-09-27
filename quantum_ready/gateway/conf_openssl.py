"""Configuración de OpenSSL del gateway: la del sistema + ``Groups``.

El módulo ``ssl`` de Python 3.14 no puede fijar el grupo X25519MLKEM768
(``set_ecdh_curve`` solo acepta curvas clásicas y ``set_groups`` llega en 3.15).
Se consigue con un archivo de configuración de OpenSSL al que apunta
``OPENSSL_CONF``, que OpenSSL lee UNA sola vez: al cargarse, es decir, al
importar ``ssl`` (o ``asyncio``, que lo importa). Por eso:

- este módulo solo importa módulos que NO cargan OpenSSL (os, re, subprocess,
  pathlib), porque se ejecuta antes que ``import ssl``;
- el archivo generado INCLUYE la configuración del sistema y solo añade
  ``Groups`` a su sección ``system_default`` (o crea la cadena de secciones que
  falte), sin sustituir lo que el sistema ya define.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

GRUPOS = "X25519MLKEM768"
NOMBRE_ARCHIVO = "openssl-gateway.cnf"
# Secciones propias, solo si la configuración del sistema no las define
_INIT, _SSL, _TLS = "qr_gateway_init", "qr_gateway_ssl", "qr_gateway_tls"

_SECCION = re.compile(r"^\[\s*([^\]]+?)\s*\]")
_INCLUDE = re.compile(r"^\.include\s*=?\s*(.+)$")
_CLAVE = re.compile(r"^([\w.$-]+)\s*=\s*(.*)$")


def directorio_trabajo() -> Path:
    """Dónde se guardan la configuración y el certificado de prueba.

    Por defecto en el HOME de Linux, no en la carpeta del proyecto: en WSL el
    proyecto vive en /mnt/c (sin permisos Unix reales y sincronizado con
    OneDrive), mal sitio para una clave privada.
    """
    return Path(os.environ.get("QR_GATEWAY_DIR", "~/.quantum_ready/gateway")).expanduser()


def ruta_conf_sistema() -> Path | None:
    """La configuración que OpenSSL usaría sin nosotros."""
    previa = os.environ.get("OPENSSL_CONF")
    if previa:
        return Path(previa)
    try:
        salida = subprocess.run(["openssl", "version", "-d"], capture_output=True,
                                text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    m = re.search(r'OPENSSLDIR:\s*"([^"]*)"', salida)
    return Path(m.group(1)) / "openssl.cnf" if m else None


def leer_secciones(ruta: Path, _visitados: set[Path] | None = None) -> dict[str, dict[str, str]]:
    """Secciones y claves de un openssl.cnf, siguiendo ``.include``.

    Parser mínimo: solo hace falta seguir la cadena
    ``openssl_conf -> ssl_conf -> system_default``.
    """
    visitados = _visitados if _visitados is not None else set()
    secciones: dict[str, dict[str, str]] = {"": {}}
    try:
        ruta = ruta.resolve()
    except OSError:
        return secciones
    if ruta in visitados:
        return secciones
    visitados.add(ruta)
    archivos = (sorted(p for p in ruta.iterdir() if p.suffix in (".cnf", ".conf"))
                if ruta.is_dir() else [ruta] if ruta.is_file() else [])
    for archivo in archivos:
        actual = ""
        for linea in archivo.read_text(encoding="utf-8", errors="replace").splitlines():
            linea = linea.split("#", 1)[0].strip()
            if m := _INCLUDE.match(linea):
                for nombre, claves in leer_secciones(Path(m.group(1).strip()), visitados).items():
                    secciones.setdefault(nombre, {}).update(claves)
            elif m := _SECCION.match(linea):
                actual = m.group(1)
                secciones.setdefault(actual, {})
            elif m := _CLAVE.match(linea):
                secciones.setdefault(actual, {})[m.group(1)] = m.group(2).strip().strip('"')
    return secciones


def contenido(conf_sistema: Path | None, grupos: str = GRUPOS) -> str:
    """Texto del archivo: incluye el del sistema y añade ``Groups``."""
    secciones = (leer_secciones(conf_sistema) if conf_sistema and conf_sistema.exists()
                 else {"": {}})
    init = secciones[""].get("openssl_conf")
    ssl_conf = secciones.get(init or "", {}).get("ssl_conf")
    tls = secciones.get(ssl_conf or "", {}).get("system_default")

    lineas = ["# Generado por quantum_ready.gateway: se regenera en cada arranque.",
              "# Incluye la configuración del sistema y solo añade Groups."]
    if init is None:  # la clave del ámbito global tiene que ir antes del .include
        init = _INIT
        lineas.append(f"openssl_conf = {init}")
    if conf_sistema and conf_sistema.exists():
        lineas.append(f".include {conf_sistema}")
    # Una sección que ya existe se amplía: OpenSSL fusiona secciones del mismo nombre
    if ssl_conf is None:
        ssl_conf = _SSL
        lineas += ["", f"[{init}]", f"ssl_conf = {ssl_conf}"]
    if tls is None:
        tls = _TLS
        lineas += ["", f"[{ssl_conf}]", f"system_default = {tls}"]
    lineas += ["", f"[{tls}]", f"Groups = {grupos}", ""]
    return "\n".join(lineas)


def preparar(directorio: Path) -> Path:
    """Escribe el archivo y devuelve su ruta (para OPENSSL_CONF)."""
    directorio.mkdir(parents=True, exist_ok=True)
    ruta = directorio / NOMBRE_ARCHIVO
    grupos = os.environ.get("QR_GATEWAY_GRUPOS", GRUPOS)
    ruta.write_text(contenido(ruta_conf_sistema(), grupos), encoding="utf-8")
    return ruta

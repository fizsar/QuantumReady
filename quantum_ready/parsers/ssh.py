"""sshd_config / ssh_config (OpenSSH)."""

from __future__ import annotations

import re
from pathlib import Path

from .base import ResultadoArchivo, lineas

# directiva en minúsculas -> nombre canónico
DIRECTIVAS_LISTA = {
    "kexalgorithms": "KexAlgorithms",
    "ciphers": "Ciphers",
    "macs": "MACs",
    "hostkeyalgorithms": "HostKeyAlgorithms",
    "pubkeyacceptedalgorithms": "PubkeyAcceptedAlgorithms",
    "pubkeyacceptedkeytypes": "PubkeyAcceptedKeyTypes",
    "casignaturealgorithms": "CASignatureAlgorithms",
    "hostbasedacceptedalgorithms": "HostbasedAcceptedAlgorithms",
    "hostbasedacceptedkeytypes": "HostbasedAcceptedKeyTypes",
}
# Si faltan, OpenSSH usa sus valores por defecto (no evaluados en la v1)
DIRECTIVAS_CLAVE = ("KexAlgorithms", "Ciphers", "MACs", "HostKeyAlgorithms")

_LINEA = re.compile(r"^(\S+?)(?:\s*=\s*|\s+)(.+)$")


def analizar(ruta: Path, texto: str) -> ResultadoArchivo:
    res = ResultadoArchivo(ruta, "ssh")
    vistas: set[str] = set()
    for n, linea in lineas(texto):
        m = _LINEA.match(linea)
        if not m:
            continue
        clave, valor = m.group(1).lower(), m.group(2).strip()
        if clave in DIRECTIVAS_LISTA:
            nombre = DIRECTIVAS_LISTA[clave]
            vistas.add(nombre)
            for token in valor.split(","):
                token = token.strip()
                # "-algo" elimina de la lista por defecto: no está habilitado
                if token and not token.startswith("-"):
                    res.anadir(n, nombre, token)
        elif clave == "hostkey":
            # El tipo de clave se deduce del nombre (ssh_host_ed25519_key...)
            fichero = re.split(r"[\\/]", valor)[-1]
            res.anadir(n, "HostKey", valor, clasificar_como=fichero)
        elif clave == "include":
            res.avisar(f"Include {valor} no se sigue en la v1; "
                       "escanea también esos archivos.", n)

    faltan = [d for d in DIRECTIVAS_CLAVE if d not in vistas]
    if faltan:
        res.avisar(f"Sin directiva explícita para {', '.join(faltan)}: se aplican "
                   "los valores por defecto de OpenSSH (dependen de la versión) "
                   "y no se han evaluado.")
    return res

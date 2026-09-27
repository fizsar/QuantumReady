"""Verificación de extremo a extremo del gateway con ``openssl s_client``.

Uso: python3 -m quantum_ready.gateway.verificar [--puerto 8443] [--ruta /]

1. Conexión con X25519MLKEM768 + petición HTTP real: comprueba en la salida
   de s_client la línea "Negotiated TLS1.3 group: X25519MLKEM768" (en una
   conexión clásica aparecería "Peer Temp Key: X25519" en su lugar) y que
   llega el JSON del backend.
2. Conexión solo con X25519 clásico: debe ser rechazada por el gateway.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from .certificado import rutas
from .conf_openssl import directorio_trabajo
from .s_client import ejecutar

GRUPO_HIBRIDO = "X25519MLKEM768"


def json_de(respuesta: str | None) -> dict | None:
    """Cuerpo JSON de una respuesta HTTP, cortado por Content-Length.

    Tras el cuerpo, s_client sigue escribiendo (volcados de los session tickets
    de TLS 1.3, que pueden contener "}"), así que no vale leer hasta el final.
    """
    if not respuesta or "\r\n\r\n" not in respuesta:
        return None
    cabecera, resto = respuesta.split("\r\n\r\n", 1)
    longitud = re.search(r"^content-length:\s*(\d+)", cabecera, re.IGNORECASE | re.MULTILINE)
    if not longitud:
        return None
    try:
        return json.loads(resto.encode("utf-8")[:int(longitud.group(1))])
    except ValueError:
        return None


def verificar(host: str, puerto: int, ruta: str = "/") -> tuple[bool, list[str]]:
    cert, _ = rutas(directorio_trabajo())
    confianza = ["-CAfile", str(cert)] if cert.exists() else []
    peticion = (f"GET {ruta} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
    lineas: list[str] = []

    hibrida = ejecutar(host, puerto, "-groups", GRUPO_HIBRIDO, "-ign_eof", *confianza,
                       entrada=peticion)
    grupo_ok = hibrida.conectado and hibrida.grupo_negociado == GRUPO_HIBRIDO
    datos = json_de(hibrida.respuesta_http)
    estado = (hibrida.respuesta_http or "").split("\r\n", 1)[0] or "(sin respuesta)"
    lineas += [
        f"{'✅' if grupo_ok else '❌'} Grupo negociado: {hibrida.grupo_negociado or '(ninguno)'}"
        f" ({hibrida.version or 'sin conexión'})"
        + (f" · clave temporal clásica: {hibrida.clave_temporal}" if hibrida.clave_temporal
           else ""),
        f"{'✅' if datos else '❌'} Respuesta del backend: {estado} {json.dumps(datos) if datos else ''}",
    ]

    clasica = ejecutar(host, puerto, "-groups", "X25519", *confianza)
    rechazo_ok = clasica.rechazado_por_el_servidor
    lineas.append(f"{'✅' if rechazo_ok else '❌'} Cliente solo X25519 clásico: "
                  f"{clasica.describir()}")
    return grupo_ok and bool(datos) and rechazo_ok, lineas


def main(argv: list[str] | None = None) -> int:
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="quantum_ready.gateway.verificar")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--puerto", type=int, default=8443)
    p.add_argument("--ruta", default="/")
    args = p.parse_args(argv)
    ok, lineas = verificar(args.host, args.puerto, args.ruta)
    print("\n".join(lineas))
    print("\nResultado:", "extremo a extremo con X25519MLKEM768 ✅" if ok else "FALLO ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

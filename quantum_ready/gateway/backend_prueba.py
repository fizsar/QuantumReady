"""Backend "heredado" de prueba: HTTP sin TLS en localhost con un JSON fijo.

Uso: python3 -m quantum_ready.gateway.backend_prueba [--puerto 8080]
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESPUESTA = {"servicio": "backend-heredado", "protegido_por": "gateway-hibrido"}


class Manejador(BaseHTTPRequestHandler):
    def _responder(self) -> None:
        cuerpo = json.dumps(RESPUESTA).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(cuerpo)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _responder

    def log_message(self, formato: str, *args) -> None:
        print(f"[backend] {self.address_string()} {formato % args}", flush=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="quantum_ready.gateway.backend_prueba")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--puerto", type=int, default=8080)
    args = p.parse_args(argv)
    servidor = ThreadingHTTPServer((args.host, args.puerto), Manejador)
    print(f"[backend] escuchando en http://{args.host}:{args.puerto} (sin TLS)", flush=True)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        servidor.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

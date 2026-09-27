"""Backend "heredado" de prueba: HTTP sin TLS en localhost, con asyncio.

Uso: python3 -m quantum_ready.gateway.backend_prueba [--puerto 8080]

Rutas:
    /         JSON fijo al momento
    /lento    el mismo JSON tras 0,5 s (asyncio.sleep: no bloquea a las demás)
    /grande   2 MB de texto, para probar cortes a mitad de respuesta
    /estado   conexiones abiertas en el backend (sin contar la propia)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

RESPUESTA = {"servicio": "backend-heredado", "protegido_por": "gateway-hibrido"}
RETARDO_LENTO_S = 0.5
TAMANO_GRANDE = 2 * 1024 * 1024


class Backend:
    def __init__(self) -> None:
        self.conexiones_abiertas = 0

    @staticmethod
    def _respuesta(cuerpo: bytes, tipo: str = "application/json") -> bytes:
        return (f"HTTP/1.1 200 OK\r\nContent-Type: {tipo}\r\n"
                f"Content-Length: {len(cuerpo)}\r\nConnection: close\r\n\r\n").encode() + cuerpo

    async def atender(self, lector: asyncio.StreamReader, escritor: asyncio.StreamWriter) -> None:
        self.conexiones_abiertas += 1
        ruta = "?"
        try:
            cabecera = await asyncio.wait_for(lector.readuntil(b"\r\n\r\n"), 10)
            ruta = cabecera.split(b"\r\n", 1)[0].decode("latin-1").split(" ")[1].split("?")[0]
            if ruta == "/lento":
                await asyncio.sleep(RETARDO_LENTO_S)
                escritor.write(self._respuesta(json.dumps(
                    {**RESPUESTA, "ruta": "/lento", "espera_s": RETARDO_LENTO_S}).encode()))
            elif ruta == "/grande":
                escritor.write(self._respuesta(b"x" * TAMANO_GRANDE, "text/plain"))
            elif ruta == "/estado":
                escritor.write(self._respuesta(json.dumps(
                    {"conexiones_abiertas": self.conexiones_abiertas - 1}).encode()))
            else:
                escritor.write(self._respuesta(json.dumps(RESPUESTA).encode()))
            await escritor.drain()
            print(f"[backend] {ruta} -> 200", flush=True)
        except (ConnectionError, TimeoutError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError, IndexError) as e:
            print(f"[backend] {ruta}: conexión cerrada ({type(e).__name__})", flush=True)
        finally:
            escritor.close()
            self.conexiones_abiertas -= 1


async def servir(host: str, puerto: int) -> None:
    backend = Backend()
    servidor = await asyncio.start_server(backend.atender, host, puerto)
    print(f"[backend] escuchando en http://{host}:{puerto} (sin TLS)", flush=True)
    async with servidor:
        await servidor.serve_forever()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="quantum_ready.gateway.backend_prueba")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--puerto", type=int, default=8080)
    args = p.parse_args(argv)
    try:
        asyncio.run(servir(args.host, args.puerto))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

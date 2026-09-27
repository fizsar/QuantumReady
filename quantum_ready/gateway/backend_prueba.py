"""Backend "heredado" de prueba: HTTP sin TLS en localhost, con asyncio.

Uso: python3 -m quantum_ready.gateway.backend_prueba [--puerto 8080]

Es un backend DE PRUEBA, no un servicio de producción: sirve, en solo
lectura, los hallazgos del escáner de la Fase 1 sobre el inventario de
ejemplo, para que el gateway proteja algo con sentido.

Rutas (solo GET):
    /salud             estado básico (``/`` es un alias)
    /hallazgos         lista resumida: servicio, algoritmo, categoría y riesgo
    /hallazgos/{id}    detalle de un hallazgo por su índice (404 si no existe)
    /lento             /salud tras 0,5 s (asyncio.sleep: no bloquea a las demás)
    /grande            2 MB de texto, para probar cortes a mitad de respuesta
    /estado            conexiones abiertas en el backend (sin contar la propia)

Los datos salen de ``informe.json`` si existe; si no, del escáner de la Fase 1
sobre ``ejemplos/inventario.yaml``. Se cargan una vez y no se modifican.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from ..escaner import escanear
from ..inventario import cargar

RAIZ = Path(__file__).resolve().parents[2]
INVENTARIO = RAIZ / "ejemplos" / "inventario.yaml"
INFORME = RAIZ / "informe.json"

RESPUESTA = {"servicio": "backend-heredado", "protegido_por": "gateway-hibrido"}
RETARDO_LENTO_S = 0.5
TAMANO_GRANDE = 2 * 1024 * 1024
_RAZONES = {200: "OK", 404: "Not Found", 405: "Method Not Allowed"}


@dataclass(frozen=True)
class Datos:
    fuente: str
    hallazgos: tuple[dict, ...]
    servicios: dict[str, dict]


def cargar_datos(inventario: Path = INVENTARIO, informe: Path = INFORME) -> Datos:
    """Hallazgos de la Fase 1 (informe.json o escaneo) y servicios del inventario."""
    inv = cargar(inventario)
    if informe.is_file():
        resultado = json.loads(informe.read_text(encoding="utf-8"))
        fuente = f"{informe.name} (generado {resultado.get('generado', '?')})"
    else:
        resultado = escanear([], inv)
        fuente = f"escaneo de {inventario.name} al arrancar"
    servicios = {s.nombre: {"tipo": s.tipo, "exposicion": s.exposicion, "alcance": s.alcance}
                 for s in inv.servicios}
    return Datos(fuente, tuple(resultado["hallazgos"]), servicios)


def resumen(indice: int, h: dict) -> dict:
    return {"id": indice, "servicio": h["servicio"], "algoritmo": h["algoritmo"],
            "categoria": h["categoria"], "riesgo": h["riesgo"]}


class Backend:
    def __init__(self, datos: Datos | None = None) -> None:
        self.conexiones_abiertas = 0
        self._datos = datos

    @property
    def datos(self) -> Datos:
        # Sin datos explícitos se cargan en el primer uso (p. ej. en tests que
        # solo usan /lento o /grande y no necesitan escanear nada).
        if self._datos is None:
            self._datos = cargar_datos()
        return self._datos

    @staticmethod
    def _respuesta(cuerpo: bytes, tipo: str = "application/json", codigo: int = 200) -> bytes:
        return (f"HTTP/1.1 {codigo} {_RAZONES[codigo]}\r\nContent-Type: {tipo}\r\n"
                f"Content-Length: {len(cuerpo)}\r\nConnection: close\r\n\r\n").encode() + cuerpo

    def _json(self, datos: object, codigo: int = 200) -> bytes:
        return self._respuesta(json.dumps(datos, ensure_ascii=False).encode("utf-8"),
                               codigo=codigo)

    def _no_encontrado(self, detalle: str) -> bytes:
        return self._json({"error": "Not Found", "detalle": detalle}, 404)

    async def responder(self, metodo: str, ruta: str) -> tuple[int, bytes]:
        if metodo != "GET":
            return 405, self._json({"error": "Method Not Allowed",
                                    "detalle": "backend de solo lectura: solo GET"}, 405)
        if ruta in ("/", "/salud"):
            return 200, self._json(RESPUESTA)
        if ruta == "/lento":
            await asyncio.sleep(RETARDO_LENTO_S)
            return 200, self._json({**RESPUESTA, "ruta": "/lento", "espera_s": RETARDO_LENTO_S})
        if ruta == "/grande":
            return 200, self._respuesta(b"x" * TAMANO_GRANDE, "text/plain")
        if ruta == "/estado":
            return 200, self._json({"conexiones_abiertas": self.conexiones_abiertas - 1})
        if ruta == "/hallazgos":
            d = self.datos
            return 200, self._json({"fuente": d.fuente, "total": len(d.hallazgos),
                                    "hallazgos": [resumen(i, h) for i, h in
                                                  enumerate(d.hallazgos)]})
        if ruta.startswith("/hallazgos/"):
            clave = ruta.removeprefix("/hallazgos/")
            d = self.datos
            if not clave.isdigit() or int(clave) >= len(d.hallazgos):
                return 404, self._no_encontrado(
                    f"no existe el hallazgo '{clave}' (ids de 0 a {len(d.hallazgos) - 1})")
            h = d.hallazgos[int(clave)]
            return 200, self._json({"id": int(clave), **h,
                                    "servicio_inventario": d.servicios.get(h["servicio"])})
        return 404, self._no_encontrado(f"ruta desconocida: {ruta}")

    async def atender(self, lector: asyncio.StreamReader, escritor: asyncio.StreamWriter) -> None:
        self.conexiones_abiertas += 1
        ruta = "?"
        try:
            cabecera = await asyncio.wait_for(lector.readuntil(b"\r\n\r\n"), 10)
            metodo, ruta = cabecera.split(b"\r\n", 1)[0].decode("latin-1").split(" ")[:2]
            ruta = ruta.split("?")[0]
            codigo, respuesta = await self.responder(metodo, ruta)
            escritor.write(respuesta)
            await escritor.drain()
            print(f"[backend] {metodo} {ruta} -> {codigo}", flush=True)
        except (ConnectionError, TimeoutError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError, ValueError) as e:
            print(f"[backend] {ruta}: conexión cerrada ({type(e).__name__})", flush=True)
        finally:
            escritor.close()
            self.conexiones_abiertas -= 1


async def servir(host: str, puerto: int, datos: Datos) -> None:
    backend = Backend(datos)
    servidor = await asyncio.start_server(backend.atender, host, puerto)
    print(f"[backend] escuchando en http://{host}:{puerto} (sin TLS) · "
          f"{len(datos.hallazgos)} hallazgos de {datos.fuente}", flush=True)
    async with servidor:
        await servidor.serve_forever()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="quantum_ready.gateway.backend_prueba")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--puerto", type=int, default=8080)
    p.add_argument("--inventario", type=Path, default=INVENTARIO)
    p.add_argument("--informe", type=Path, default=INFORME,
                   help="Resultado de la Fase 1; si no existe, se escanea el inventario.")
    args = p.parse_args(argv)
    try:
        asyncio.run(servir(args.host, args.puerto, cargar_datos(args.inventario, args.informe)))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Prueba de carga del gateway: clientes TLS simultáneos, mitad a / y mitad a /lento.

Uso: python3 -m quantum_ready.gateway.carga [--clientes 30] [--puerto 8443]

Mide el mismo lote de peticiones dos veces: todas a la vez y una tras otra.
Con /lento tardando 0,5 s, la ejecución secuencial no puede bajar de
(clientes / 2) x 0,5 s; si el proxy atiende de verdad en paralelo, la
concurrente debe quedarse cerca de 0,5 s.

El cliente usa los grupos por defecto de OpenSSL 3.5, que incluyen
X25519MLKEM768; como el gateway solo admite ese grupo, toda conexión que
termina con éxito ha usado el intercambio híbrido.
"""

from __future__ import annotations

import argparse
import asyncio
import ssl
import statistics
import sys
import time
from dataclasses import dataclass

from .backend_prueba import RETARDO_LENTO_S
from .certificado import rutas
from .conf_openssl import directorio_trabajo


@dataclass(frozen=True)
class Resultado:
    ruta: str
    estado: int | None
    segundos: float
    error: str | None = None


def contexto_cliente() -> ssl.SSLContext:
    cert, _ = rutas(directorio_trabajo())
    ctx = ssl.create_default_context(cafile=str(cert))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


async def peticion(host: str, puerto: int, ruta: str, ctx: ssl.SSLContext) -> Resultado:
    inicio = time.perf_counter()
    try:
        lector, escritor = await asyncio.open_connection(host, puerto, ssl=ctx,
                                                         server_hostname="localhost")
        escritor.write(f"GET {ruta} HTTP/1.1\r\nHost: localhost\r\n"
                       "Connection: close\r\n\r\n".encode())
        await escritor.drain()
        respuesta = await lector.read()
        escritor.close()
        estado = int(respuesta.split(b" ", 2)[1]) if respuesta.startswith(b"HTTP/") else None
        return Resultado(ruta, estado, time.perf_counter() - inicio)
    except (OSError, ssl.SSLError, ValueError) as e:
        return Resultado(ruta, None, time.perf_counter() - inicio, f"{type(e).__name__}: {e}")


def rutas_lote(clientes: int) -> list[str]:
    return ["/lento" if i % 2 else "/" for i in range(clientes)]


async def concurrente(host: str, puerto: int, clientes: int) -> tuple[float, list[Resultado]]:
    ctx = contexto_cliente()
    inicio = time.perf_counter()
    resultados = await asyncio.gather(*(peticion(host, puerto, r, ctx)
                                        for r in rutas_lote(clientes)))
    return time.perf_counter() - inicio, list(resultados)


async def secuencial(host: str, puerto: int, clientes: int) -> tuple[float, list[Resultado]]:
    ctx = contexto_cliente()
    inicio = time.perf_counter()
    resultados = [await peticion(host, puerto, r, ctx) for r in rutas_lote(clientes)]
    return time.perf_counter() - inicio, resultados


def _resumen(nombre: str, total: float, resultados: list[Resultado]) -> list[str]:
    lineas = [f"{nombre}: {total:.2f} s en total"]
    for ruta in ("/", "/lento"):
        tiempos = [r.segundos for r in resultados if r.ruta == ruta]
        ok = sum(r.estado == 200 for r in resultados if r.ruta == ruta)
        lineas.append(f"    {ruta:<7} {ok}/{len(tiempos)} con 200 · por petición: mín "
                      f"{min(tiempos):.3f} s, mediana {statistics.median(tiempos):.3f} s, "
                      f"máx {max(tiempos):.3f} s")
    lineas += [f"    ERROR {r.ruta}: {r.error or r.estado}" for r in resultados
               if r.estado != 200]
    return lineas


def main(argv: list[str] | None = None) -> int:
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="quantum_ready.gateway.carga")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--puerto", type=int, default=8443)
    p.add_argument("--clientes", type=int, default=30)
    p.add_argument("--sin-secuencial", action="store_true",
                   help="Medir solo la ejecución concurrente.")
    args = p.parse_args(argv)

    lentas = args.clientes // 2
    print(f"{args.clientes} clientes TLS contra https://{args.host}:{args.puerto} "
          f"({args.clientes - lentas} a /, {lentas} a /lento de {RETARDO_LENTO_S} s)\n")
    t_conc, r_conc = asyncio.run(concurrente(args.host, args.puerto, args.clientes))
    print("\n".join(_resumen("Concurrente (todas a la vez)", t_conc, r_conc)))
    todo_ok = all(r.estado == 200 for r in r_conc)
    if not args.sin_secuencial:
        t_sec, r_sec = asyncio.run(secuencial(args.host, args.puerto, args.clientes))
        print("\n".join(_resumen("Secuencial (una tras otra)", t_sec, r_sec)))
        todo_ok &= all(r.estado == 200 for r in r_sec)
        print(f"\nMínimo teórico secuencial: {lentas} x {RETARDO_LENTO_S} s = "
              f"{lentas * RETARDO_LENTO_S:.1f} s · concurrente {t_sec / t_conc:.1f} veces "
              "más rápido que secuencial")
    return 0 if todo_ok else 1


if __name__ == "__main__":
    sys.exit(main())

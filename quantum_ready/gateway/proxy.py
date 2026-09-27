"""Fase 5 (hito 1): gateway TLS con intercambio de claves híbrido X25519MLKEM768.

cliente --TLS 1.3 híbrido--> proxy (:8443) --HTTP sin TLS--> backend heredado

Uso (Linux con Python >= 3.14 y OpenSSL >= 3.5, p. ej. Ubuntu 26.04 en WSL2):
    python3 -m quantum_ready.gateway.backend_prueba &
    python3 -m quantum_ready.gateway.proxy [--puerto 8443] [--backend 127.0.0.1:8080]
"""

# ── 1. OPENSSL_CONF, lo primero: OpenSSL lee su configuración UNA vez, al
#       cargarse (al importar ssl, asyncio o hashlib). Fijarla después no tiene
#       efecto y el servidor aceptaría X25519 clásico sin avisar.
import os
import sys

if {"ssl", "_ssl", "_hashlib"} & sys.modules.keys():
    sys.exit("ERROR: OpenSSL ya estaba cargado antes de fijar OPENSSL_CONF; la "
             "restricción a X25519MLKEM768 no tendría efecto. Ejecuta el gateway "
             "como programa: python3 -m quantum_ready.gateway.proxy")

from quantum_ready.gateway import conf_openssl  # noqa: E402  (no carga OpenSSL)

DIRECTORIO = conf_openssl.directorio_trabajo()
os.environ["OPENSSL_CONF"] = str(conf_openssl.preparar(DIRECTORIO))

# ── 2. A partir de aquí ya se puede cargar OpenSSL ─────────────────────────────
import argparse  # noqa: E402
import asyncio  # noqa: E402
import ssl  # noqa: E402
from dataclasses import dataclass  # noqa: E402

from quantum_ready.gateway import certificado, s_client  # noqa: E402
from quantum_ready.gateway.reenvio import GRUPO_HIBRIDO, reenviar  # noqa: E402

TAMANO_MAXIMO_CABECERA = 64 * 1024


class ErrorArranque(RuntimeError):
    pass


# --- Contexto TLS ------------------------------------------------------------------
def crear_contexto(cert, clave) -> ssl.SSLContext:
    """TLS 1.3 como mínimo; los grupos los fija OPENSSL_CONF (Groups = X25519MLKEM768)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, clave)
    return ctx


# --- Autotest de arranque --------------------------------------------------------------
@dataclass(frozen=True)
class Caso:
    descripcion: str
    opciones: tuple[str, ...]
    debe_conectar: bool


CASOS_AUTOTEST = (
    Caso("cliente híbrido X25519MLKEM768 (control positivo)",
         ("-groups", GRUPO_HIBRIDO), True),
    Caso("cliente con grupos solo clásicos", ("-groups", "X25519:secp256r1:secp384r1:x448"),
         False),
    Caso("cliente que intenta bajar a TLS 1.2", ("-tls1_2",), False),
)


async def autotest(ctx: ssl.SSLContext) -> list[str]:
    """Prueba el contexto con openssl s_client antes de aceptar tráfico real.

    Se hace sobre un servidor temporal en un puerto efímero con el MISMO
    contexto, así el puerto real no se abre hasta que el autotest pasa.
    Lanza ErrorArranque si el servidor acepta algo que debería rechazar.
    """
    async def cerrar(_lector, escritor):
        escritor.close()

    servidor = await asyncio.start_server(cerrar, "127.0.0.1", 0, ssl=ctx)
    puerto = servidor.sockets[0].getsockname()[1]
    informe, fallos = [], []
    try:
        for caso in CASOS_AUTOTEST:
            r = await s_client.ejecutar_async("127.0.0.1", puerto, *caso.opciones)
            if caso.debe_conectar:
                ok = r.conectado and r.grupo_negociado == GRUPO_HIBRIDO
            else:
                ok = r.rechazado_por_el_servidor
            detalle = r.describir()
            informe.append(f"  {'✅' if ok else '❌'} {caso.descripcion}: {detalle}")
            if not ok:
                fallos.append(caso.descripcion)
    finally:
        servidor.close()
        await servidor.wait_closed()
    if fallos:
        raise ErrorArranque("\n".join(informe) + "\n\nEl autotest de seguridad ha fallado ("
                            + "; ".join(fallos) + "). El gateway NO arranca: aceptaría "
                            "conexiones sin intercambio híbrido o no puede verificarlo.")
    return informe


# --- Arranque ---------------------------------------------------------------------------
def _direccion(texto: str) -> tuple[str, int]:
    host, _, puerto = texto.rpartition(":")
    return host or "127.0.0.1", int(puerto)


async def arrancar(host: str, puerto: int, backend: tuple[str, int]) -> None:
    if ssl.OPENSSL_VERSION_INFO < (3, 5):
        raise ErrorArranque(f"El módulo ssl usa {ssl.OPENSSL_VERSION}; X25519MLKEM768 "
                            "requiere OpenSSL 3.5 o posterior.")
    cert, clave = certificado.asegurar(DIRECTORIO)
    ctx = crear_contexto(cert, clave)
    print(f"[proxy] {ssl.OPENSSL_VERSION} · OPENSSL_CONF={os.environ['OPENSSL_CONF']}")
    print("[proxy] Autotest de seguridad:")
    try:
        informe = await autotest(ctx)
    except FileNotFoundError:
        raise ErrorArranque("No se encuentra el comando openssl, necesario para "
                            "verificar el grupo negociado.") from None
    print("\n".join(informe))

    servidor = await asyncio.start_server(
        lambda r, w: reenviar(r, w, backend), host, puerto, ssl=ctx,
        limit=TAMANO_MAXIMO_CABECERA)
    print(f"[proxy] escuchando en https://{host}:{puerto} -> http://{backend[0]}:{backend[1]}"
          f" (solo {GRUPO_HIBRIDO}, TLS 1.3)")
    print("LISTO", flush=True)
    async with servidor:
        await servidor.serve_forever()


def main(argv: list[str] | None = None) -> int:
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="quantum_ready.gateway.proxy",
                                description="Gateway TLS con intercambio híbrido "
                                            "X25519MLKEM768 hacia un backend HTTP.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--puerto", type=int, default=8443)
    p.add_argument("--backend", type=_direccion, default=("127.0.0.1", 8080),
                   help="host:puerto del backend HTTP sin TLS (por defecto 127.0.0.1:8080)")
    args = p.parse_args(argv)
    try:
        asyncio.run(arrancar(args.host, args.puerto, args.backend))
    except ErrorArranque as e:
        print(f"[proxy] ERROR:\n{e}", file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

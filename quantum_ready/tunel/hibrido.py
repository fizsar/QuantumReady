"""Simulación del intercambio de claves híbrido ML-KEM-768 + X25519 (Fase 2).

Uso: python -m quantum_ready.tunel [-o resultados_intercambio.json]
"""

from __future__ import annotations

import argparse
import hmac
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .actores import (Atacante, Cliente, ClavesPublicasServidor, Evento, Intento,
                      RespuestaCliente, Servidor)
from .cripto import ESQUEMA, LONGITUD_CLAVE_FINAL

BYTES_INICIO, BYTES_FIN = 8, 4  # extracto hexadecimal: 8 primeros … 4 últimos
# Tamaño de una clave pública X25519: referencia de un intercambio solo clásico
X25519_PUBLICA = 32


@dataclass
class ResultadoIntercambio:
    registro: list[Evento]
    pasos: list[tuple[str, int, int]]  # (título, primer evento, último evento)
    claves_servidor: ClavesPublicasServidor
    respuesta_cliente: RespuestaCliente
    clave_cliente: bytes
    clave_servidor: bytes
    intentos_atacante: list[Intento]

    @property
    def coinciden(self) -> bool:
        return hmac.compare_digest(self.clave_cliente, self.clave_servidor)

    @property
    def atacante_coincide(self) -> bool:
        return any(hmac.compare_digest(i.clave, self.clave_servidor)
                   for i in self.intentos_atacante)


def ejecutar_intercambio() -> ResultadoIntercambio:
    registro: list[Evento] = []
    pasos: list[tuple[str, int, int]] = []

    def paso(titulo: str, desde: int) -> None:
        pasos.append((titulo, desde, len(registro)))

    i = len(registro)
    servidor = Servidor(registro)
    cliente = Cliente(registro)
    paso("1. Generación de claves", i)

    i = len(registro)
    claves_servidor = servidor.claves_publicas()
    paso("2. Intercambio de claves públicas: Servidor → Cliente", i)

    i = len(registro)
    respuesta = cliente.responder(claves_servidor)
    paso("3. Encapsulación (Cliente) y respuesta Cliente → Servidor", i)

    i = len(registro)
    servidor.recibir(respuesta)
    paso("4. Decapsulación (Servidor)", i)

    i = len(registro)
    clave_cliente = cliente.derivar()
    clave_servidor = servidor.derivar()
    paso("5. Combinación: HKDF-SHA384(secreto_ML-KEM || secreto_X25519)", i)

    i = len(registro)
    atacante = Atacante(registro)
    atacante.observar(claves_servidor, respuesta)
    intentos = atacante.intentar()
    paso("6. Ataque: solo con los datos públicos interceptados", i)

    return ResultadoIntercambio(registro, pasos, claves_servidor, respuesta,
                                clave_cliente, clave_servidor, intentos)


# --- Salida -----------------------------------------------------------------------
def extracto(datos: bytes) -> str:
    if len(datos) <= BYTES_INICIO + BYTES_FIN:
        return datos.hex()
    return f"{datos[:BYTES_INICIO].hex()}…{datos[-BYTES_FIN:].hex()}"


def tamanos(r: ResultadoIntercambio) -> dict[str, int]:
    return {
        "x25519_clave_publica": len(r.claves_servidor.x25519),
        "mlkem768_clave_publica": len(r.claves_servidor.mlkem768),
        "mlkem768_ciphertext": len(r.respuesta_cliente.mlkem768_ciphertext),
        "clave_final": len(r.clave_servidor),
    }


def resultados_json(r: ResultadoIntercambio) -> dict:
    """Tamaños para el análisis de overhead de la Fase 3."""
    t = tamanos(r)
    servidor_a_cliente = t["x25519_clave_publica"] + t["mlkem768_clave_publica"]
    cliente_a_servidor = t["x25519_clave_publica"] + t["mlkem768_ciphertext"]
    return {
        "fase": 2,
        "esquema": ESQUEMA,
        "generado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tamanos_bytes": t,
        "bytes_en_red": {
            "servidor_a_cliente": servidor_a_cliente,
            "cliente_a_servidor": cliente_a_servidor,
            "total": servidor_a_cliente + cliente_a_servidor,
        },
        "referencia_solo_x25519": {
            "servidor_a_cliente": X25519_PUBLICA,
            "cliente_a_servidor": X25519_PUBLICA,
            "total": 2 * X25519_PUBLICA,
        },
        "verificacion": {
            "cliente_servidor_coinciden": r.coinciden,
            "atacante_coincide": r.atacante_coincide,
        },
    }


def informe_texto(r: ResultadoIntercambio) -> str:
    s = [f"INTERCAMBIO DE CLAVES HÍBRIDO · {ESQUEMA}"]
    for titulo, desde, hasta in r.pasos:
        s.append("")
        s.append(titulo)
        for e in r.registro[desde:hasta]:
            red = "📡" if e.viaja_por_la_red else "  "
            s.append(f"  {red} {e.actor:<9} {e.elemento:<52} {len(e.datos):>5} B  "
                     f"{extracto(e.datos)}")

    s.append("")
    s.append("Intentos del Atacante:")
    for intento in r.intentos_atacante:
        ok = hmac.compare_digest(intento.clave, r.clave_servidor)
        s.append(f"  {'❌ ¡coincide!' if ok else '✅ no coincide'}  {intento.estrategia}"
                 f"  ({extracto(intento.clave)})")

    t = tamanos(r)
    datos = resultados_json(r)
    filas = [
        ("Clave pública X25519", t["x25519_clave_publica"]),
        ("Clave pública ML-KEM-768", t["mlkem768_clave_publica"]),
        ("Ciphertext ML-KEM-768", t["mlkem768_ciphertext"]),
        ("Clave final derivada", t["clave_final"]),
    ]
    s.append("")
    s.append("RESUMEN DE TAMAÑOS")
    s.append(f"  {'Elemento':<28} {'Bytes':>6}")
    s.append(f"  {'─' * 28} {'─' * 6}")
    s.extend(f"  {nombre:<28} {n:>6}" for nombre, n in filas)
    red, clasico = datos["bytes_en_red"], datos["referencia_solo_x25519"]
    s.append(f"  {'─' * 28} {'─' * 6}")
    s.append(f"  {'Total en red (híbrido)':<28} {red['total']:>6}")
    s.append(f"  {'Total en red (solo X25519)':<28} {clasico['total']:>6}")

    atacante = r.atacante_coincide
    s.append("")
    s.append(f"{'✅' if r.coinciden else '❌'} Cliente y Servidor "
             f"{'obtienen la misma' if r.coinciden else 'NO obtienen la misma'} "
             f"clave final ({LONGITUD_CLAVE_FINAL} bytes)")
    fallidos = sum(1 for i in r.intentos_atacante
                   if not hmac.compare_digest(i.clave, r.clave_servidor))
    s.append(f"{'❌' if atacante else '✅'} El Atacante "
             f"{'SÍ obtiene' if atacante else 'NO obtiene'} la clave "
             f"({fallidos}/{len(r.intentos_atacante)} intentos fallidos)")
    return "\n".join(s)


def main(argv: list[str] | None = None) -> int:
    for flujo in (sys.stdout, sys.stderr):
        if hasattr(flujo, "reconfigure"):
            flujo.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(
        prog="quantum_ready.tunel",
        description="Simula un intercambio de claves híbrido ML-KEM-768 + X25519.")
    p.add_argument("-o", "--salida", type=Path,
                   default=Path("resultados_intercambio.json"),
                   help="JSON con los tamaños (por defecto resultados_intercambio.json).")
    args = p.parse_args(argv)

    resultado = ejecutar_intercambio()
    print(informe_texto(resultado))
    args.salida.write_text(
        json.dumps(resultados_json(resultado), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print(f"\nTamaños guardados en {args.salida}")
    return 0 if resultado.coinciden and not resultado.atacante_coincide else 1

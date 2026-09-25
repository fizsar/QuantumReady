"""VPN: strongSwan (ipsec.conf / swanctl.conf) y WireGuard (wg0.conf)."""

from __future__ import annotations

import re
from pathlib import Path

from ..reglas import ALGORITMOS, clasificar
from .base import ResultadoArchivo, lineas

_CLAVE = re.compile(r"^([\w.-]+)\s*=\s*(.*)$")

# ipsec.conf (ike, esp, ah) y swanctl.conf (proposals, esp_proposals...)
PROPUESTAS = {"ike", "esp", "ah", "proposals", "esp_proposals", "ah_proposals"}
AUTENTICACION = {"authby", "leftauth", "rightauth", "leftauth2", "rightauth2", "auth"}
_SIMETRICA = {"psk", "secret", "xauthpsk", "never"}
_INTERCAMBIO_CLASICO = {"DH", "ECDH"}


# ---------------------------------------------------------------------------
# IPsec (strongSwan)
# ---------------------------------------------------------------------------
def _propuesta(res: ResultadoArchivo, n: int, directiva: str, propuesta: str) -> None:
    """Una propuesta como 'aes256-sha256-x25519-ke1_mlkem768'.

    Si incluye ML-KEM junto a un intercambio clásico, es un intercambio híbrido
    y el componente clásico no se marca como crítico por separado.
    """
    detectados = [a for comp in propuesta.split("-") if comp for a in clasificar(comp)]
    if not detectados:
        res.anadir(n, directiva, propuesta)  # queda como no reconocido
        return
    if any(a.id == "ML-KEM" for a in detectados):
        clasico = any(a.id in _INTERCAMBIO_CLASICO for a in detectados)
        detectados = [a for a in detectados
                      if a.id not in _INTERCAMBIO_CLASICO | {"ML-KEM"}]
        detectados.insert(0, ALGORITMOS["ML-KEM-HIBRIDO" if clasico else "ML-KEM"])
    for algoritmo in detectados:
        res.anadir_algoritmo(n, directiva, propuesta, algoritmo)


def analizar_ipsec(ruta: Path, texto: str) -> ResultadoArchivo:
    res = ResultadoArchivo(ruta, "ipsec")
    hay_propuestas = False
    for n, linea in lineas(texto):
        m = _CLAVE.match(linea)
        if not m:
            continue
        clave, valor = m.group(1).lower(), m.group(2).strip().strip('"')
        if clave in PROPUESTAS:
            hay_propuestas = True
            for propuesta in valor.split(","):
                propuesta = propuesta.strip().rstrip("!").lower()
                if propuesta == "default":
                    res.avisar(f"{clave}: 'default' usa las propuestas por "
                               "defecto de strongSwan y no se han evaluado.", n)
                elif propuesta:
                    _propuesta(res, n, clave, propuesta)
        elif clave in AUTENTICACION:
            metodo = valor.lower()
            if metodo in _SIMETRICA:
                continue  # clave precompartida: simétrica, no afectada por Shor
            if metodo.startswith("pubkey"):
                res.avisar(f"{clave}={valor}: el algoritmo depende del "
                           "certificado; añádelo al inventario para evaluarlo.", n)
                continue
            res.anadir(n, clave, valor)
        elif clave in ("leftcert", "rightcert", "certs"):
            res.avisar(f"Certificado referenciado: {valor}. Si no está ya en el inventario, "
                       "añádelo para analizar su clave y su firma.", n)
        elif clave == "keyexchange" and valor.lower() == "ikev1":
            res.avisar("keyexchange=ikev1: IKEv1 está obsoleto; migrar a IKEv2 "
                       "(necesario para el intercambio híbrido con ML-KEM).", n)

    if not hay_propuestas:
        res.avisar("Sin propuestas ike/esp explícitas: strongSwan usa sus "
                   "propuestas por defecto (dependen de la versión) y no se han "
                   "evaluado.")
    return res


# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------
def analizar_wireguard(ruta: Path, texto: str) -> ResultadoArchivo:
    """WireGuard tiene criptografía fija (Curve25519, ChaCha20, BLAKE2s).

    Lo único configurable que cambia el riesgo cuántico es la PresharedKey de
    cada peer: sin ella 🔴 Crítico, con ella 🟡 Advertencia.
    """
    res = ResultadoArchivo(ruta, "wireguard")
    peers: list[dict] = []
    seccion = None
    for n, linea in lineas(texto):
        if linea.startswith("["):
            seccion = linea.strip("[]").strip().lower()
            if seccion == "peer":
                peers.append({"linea": n, "psk": False, "clave": None})
            continue
        m = _CLAVE.match(linea)
        if seccion != "peer" or not m:
            continue
        clave, valor = m.group(1).lower(), m.group(2).strip()
        if clave == "presharedkey" and valor:
            peers[-1]["psk"] = True
        elif clave == "publickey":
            peers[-1]["clave"] = valor

    if not peers:
        res.avisar("No hay secciones [Peer]: no se puede evaluar el handshake.")
    for i, peer in enumerate(peers, start=1):
        valor = f"peer {i}"
        if peer["clave"]:
            valor += f" (PublicKey {peer['clave'][:12]}…)"
        algoritmo = ALGORITMOS["WG-CON-PSK" if peer["psk"] else "WG-SIN-PSK"]
        res.anadir_algoritmo(peer["linea"], "[Peer]", valor, algoritmo)
    return res

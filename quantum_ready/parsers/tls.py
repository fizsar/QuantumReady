"""nginx y Apache (mod_ssl): protocolos, cifrados y grupos de intercambio."""

from __future__ import annotations

import re
from pathlib import Path

from ..reglas import clasificar_protocolo
from .base import ResultadoArchivo, lineas

# Alias de OpenSSL cuyo contenido real depende de la versión instalada
ALIAS_OPENSSL = {
    "all", "default", "complementofdefault", "complementofall", "high",
    "medium", "low", "export", "null", "enull", "anull", "compatible",
}
_TODOS_APACHE = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


# ---------------------------------------------------------------------------
# Comunes
# ---------------------------------------------------------------------------
def _protocolos(res: ResultadoArchivo, n: int, directiva: str,
                versiones: list[str]) -> None:
    for version in versiones:
        algoritmo = clasificar_protocolo(version)
        if algoritmo:
            res.anadir_algoritmo(n, directiva, version, algoritmo)
        else:
            res.anadir(n, directiva, version)


def _cbc_implicito(token: str) -> bool:
    """Los nombres OpenSSL (``ECDHE-RSA-AES128-SHA256``) sin GCM/CCM/ChaCha son CBC."""
    t = token.lower()
    return ("-" in t and not t.startswith("tls_")
            and re.search(r"aes|camellia|aria|seed|des", t) is not None
            and re.search(r"gcm|ccm|chacha|poly1305", t) is None)


def _cifrados(res: ResultadoArchivo, n: int, directiva: str, cadena: str) -> None:
    for token in re.split(r"[:,\s]+", cadena.strip("'\"")):
        if not token or token[0] in "!-" or token.startswith("@"):
            continue  # exclusiones (!X, -X) y opciones (@STRENGTH, @SECLEVEL)
        token = token.lstrip("+")
        if token.lower() in ALIAS_OPENSSL:
            res.avisar(f"{directiva}: el alias '{token}' depende de la versión "
                       "de OpenSSL; lista los cifrados explícitamente para "
                       "poder evaluarlos.", n)
            continue
        res.anadir(n, directiva, token, cbc_implicito=_cbc_implicito(token))


def _grupos(res: ResultadoArchivo, n: int, directiva: str, cadena: str) -> None:
    for token in re.split(r"[:,\s]+", cadena.strip("'\"")):
        if not token:
            continue
        if token.lower() == "auto":
            res.avisar(f"{directiva} auto: los grupos dependen de la versión de "
                       "OpenSSL y no se han evaluado.", n)
            continue
        res.anadir(n, directiva, token)


def _conf_command(res: ResultadoArchivo, n: int, directiva: str, valor: str) -> None:
    """ssl_conf_command / SSLOpenSSLConfCmd: Groups, Curves, Ciphersuites..."""
    partes = valor.split(None, 1)
    if len(partes) < 2:
        return
    orden, argumento = partes[0].lower(), partes[1]
    etiqueta = f"{directiva} {partes[0]}"
    if orden in ("groups", "curves"):
        _grupos(res, n, etiqueta, argumento)
    elif orden in ("ciphersuites", "ciphers", "ciphersuite", "cipherstring"):
        _cifrados(res, n, etiqueta, argumento)
    elif orden in ("protocol", "minprotocol", "maxprotocol"):
        _protocolos(res, n, etiqueta, re.split(r"[,\s]+", argumento.strip("'\"")))


# ---------------------------------------------------------------------------
# nginx
# ---------------------------------------------------------------------------
def analizar_nginx(ruta: Path, texto: str) -> ResultadoArchivo:
    res = ResultadoArchivo(ruta, "nginx")
    vistas: set[str] = set()
    for n, linea in lineas(texto):
        for sentencia in linea.split(";"):
            partes = sentencia.strip().split(None, 1)
            if len(partes) < 2:
                continue
            clave, valor = partes[0].lower(), partes[1].strip().strip("'\"")
            vistas.add(clave)
            if clave in ("ssl_protocols", "proxy_ssl_protocols"):
                _protocolos(res, n, clave, valor.split())
            elif clave in ("ssl_ciphers", "proxy_ssl_ciphers"):
                _cifrados(res, n, clave, valor)
            elif clave == "ssl_ecdh_curve":
                _grupos(res, n, clave, valor)
            elif clave == "ssl_conf_command":
                _conf_command(res, n, clave, valor)
            elif clave in ("ssl_certificate", "proxy_ssl_certificate"):
                res.avisar(f"Certificado referenciado: {valor}. Si no está ya en el "
                           "inventario, añádelo para analizar su clave y su firma.", n)

    if "ssl_protocols" not in vistas:
        res.avisar("ssl_protocols no definido: nginx usa sus valores por defecto "
                   "(TLSv1.2 y TLSv1.3 desde la 1.23.4; incluye TLSv1 y TLSv1.1 "
                   "en versiones anteriores).")
    if "ssl_ciphers" not in vistas:
        res.avisar("ssl_ciphers no definido: nginx usa 'HIGH:!aNULL:!MD5', que "
                   "depende de la versión de OpenSSL y no se ha evaluado.")
    return res


# ---------------------------------------------------------------------------
# Apache
# ---------------------------------------------------------------------------
def _versiones_apache(valor: str) -> list[str]:
    """Resuelve 'all -TLSv1 -TLSv1.1' al conjunto de versiones habilitadas."""
    activas: list[str] = []
    for token in valor.split():
        signo = "-" if token.startswith("-") else "+"
        nombre = token.lstrip("+-")
        grupo = _TODOS_APACHE if nombre.lower() == "all" else [nombre]
        for version in grupo:
            iguales = [v for v in activas if v.lower() == version.lower()]
            if signo == "+" and not iguales:
                activas.append(version)
            elif signo == "-":
                for v in iguales:
                    activas.remove(v)
    return activas


def analizar_apache(ruta: Path, texto: str) -> ResultadoArchivo:
    res = ResultadoArchivo(ruta, "apache")
    vistas: set[str] = set()
    for n, linea in lineas(texto):
        partes = linea.split(None, 1)
        if len(partes) < 2:
            continue
        directiva, valor = partes[0], partes[1].strip().strip("'\"")
        clave = directiva.lower()
        vistas.add(clave)
        if clave in ("sslprotocol", "sslproxyprotocol"):
            _protocolos(res, n, directiva, _versiones_apache(valor))
        elif clave in ("sslciphersuite", "sslproxyciphersuite"):
            # Forma opcional: SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384
            trozos = valor.split(None, 1)
            if len(trozos) == 2 and trozos[0].upper() in ("SSL", "TLSV1.3"):
                valor = trozos[1]
            _cifrados(res, n, directiva, valor)
        elif clave == "sslopensslconfcmd":
            _conf_command(res, n, directiva, valor)
        elif clave in ("sslcertificatefile", "sslproxymachinecertificatefile"):
            res.avisar(f"Certificado referenciado: {valor}. Si no está ya en el "
                       "inventario, añádelo para analizar su clave y su firma.", n)

    if "sslprotocol" not in vistas:
        res.avisar("SSLProtocol no definido: Apache usa sus valores por defecto "
                   "(dependen de la versión) y no se han evaluado.")
    if "sslciphersuite" not in vistas:
        res.avisar("SSLCipherSuite no definido: Apache usa los cifrados por "
                   "defecto de OpenSSL y no se han evaluado.")
    return res

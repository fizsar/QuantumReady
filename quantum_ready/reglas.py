"""Libro de reglas de cripto-agilidad (Fase 1).

Este archivo es la única fuente de verdad sobre clasificaciones. Tiene dos tablas:

- ``ALGORITMOS``: qué es cada algoritmo, su categoría, por qué y qué hacer.
- ``PATRONES``: cómo se reconoce cada algoritmo dentro de un nombre de
  configuración (``ecdh-sha2-nistp256``, ``ECDHE-RSA-AES128-GCM-SHA256``...).

El ORDEN de ``PATRONES`` importa: los híbridos post-cuánticos se comprueban
primero y, si coinciden, cortan la búsqueda. Así ``mlkem768x25519-sha256`` no
se marca como ECDH por contener ``x25519``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import Enum


class Categoria(str, Enum):
    CRITICO = "critico"
    OBSOLETO = "obsoleto"
    ADVERTENCIA = "advertencia"
    ACEPTABLE = "aceptable"
    POST_CUANTICO = "post_cuantico"

    @property
    def emoji(self) -> str:
        return _EMOJI[self]

    @property
    def etiqueta(self) -> str:
        return _ETIQUETA[self]


_EMOJI = {
    Categoria.CRITICO: "🔴",
    Categoria.OBSOLETO: "⚪",
    Categoria.ADVERTENCIA: "🟡",
    Categoria.ACEPTABLE: "🟢",
    Categoria.POST_CUANTICO: "🔵",
}
_ETIQUETA = {
    Categoria.CRITICO: "Crítico",
    Categoria.OBSOLETO: "Obsoleto",
    Categoria.ADVERTENCIA: "Advertencia",
    Categoria.ACEPTABLE: "Aceptable",
    Categoria.POST_CUANTICO: "Post-cuántico",
}


@dataclass(frozen=True)
class Algoritmo:
    id: str
    nombre: str
    categoria: Categoria
    recomendacion: str
    motivo: str


C = Categoria

# ---------------------------------------------------------------------------
# Tabla de algoritmos
# ---------------------------------------------------------------------------
ALGORITMOS: dict[str, Algoritmo] = {
    a.id: a
    for a in [
        # 🔴 Crítico: roto por Shor
        Algoritmo("RSA", "RSA", C.CRITICO,
                  "Migrar a híbrido RSA/ECC + ML-KEM",
                  "Roto por Shor (factorización de enteros)."),
        Algoritmo("DH", "DH / DHE", C.CRITICO,
                  "Migrar a X25519 + ML-KEM híbrido",
                  "Roto por Shor (logaritmo discreto)."),
        Algoritmo("ECDH", "ECDH / ECDHE", C.CRITICO,
                  "Migrar a versión híbrida con ML-KEM "
                  "(mlkem768x25519-sha256 en SSH, X25519MLKEM768 en TLS)",
                  "Roto por Shor (logaritmo discreto en curvas elípticas)."),
        Algoritmo("ECDSA", "ECDSA / Ed25519", C.CRITICO,
                  "Migrar a ML-DSA o firma híbrida",
                  "Roto por Shor (logaritmo discreto en curvas elípticas)."),
        Algoritmo("DSA", "DSA", C.CRITICO,
                  "Eliminar; migrar a ML-DSA o firma híbrida",
                  "Roto por Shor y además obsoleto: OpenSSH lo deshabilita "
                  "por defecto desde la versión 7.0."),
        # ⚪ Obsoleto: roto por medios clásicos
        Algoritmo("3DES", "3DES / DES", C.OBSOLETO,
                  "Eliminar, usar AES-256",
                  "Bloque de 64 bits (Sweet32); roto por medios clásicos."),
        Algoritmo("RC4", "RC4", C.OBSOLETO,
                  "Eliminar, usar AES-256 o ChaCha20",
                  "Sesgos estadísticos explotables; prohibido en TLS (RFC 7465)."),
        Algoritmo("MD5", "MD5", C.OBSOLETO,
                  "Eliminar, usar SHA-384/512",
                  "Colisiones prácticas desde 2004."),
        Algoritmo("SHA-1", "SHA-1", C.OBSOLETO,
                  "Sustituir por SHA-384/512",
                  "Colisión práctica demostrada (SHAttered, 2017); "
                  "nada que ver con Grover."),
        Algoritmo("TLS-1.0/1.1", "TLS 1.0 / TLS 1.1", C.OBSOLETO,
                  "Forzar TLS 1.3",
                  "Protocolo obsoleto (BEAST, admite cifrados débiles); "
                  "retirado por RFC 8996."),
        Algoritmo("SSL", "SSL 2.0 / SSL 3.0", C.OBSOLETO,
                  "Eliminar; forzar TLS 1.3",
                  "Protocolo roto (POODLE)."),
        # 🟡 Advertencia: debilitado por Grover
        Algoritmo("AES-128", "AES-128", C.ADVERTENCIA,
                  "Subir a AES-256",
                  "Grover reduce su seguridad efectiva a 64 bits."),
        # 🟢 Aceptable
        Algoritmo("AES-192", "AES-192", C.ACEPTABLE, "Sin urgencia",
                  "Grover lo deja en 96 bits efectivos; suficiente hoy."),
        Algoritmo("AES-256", "AES-256", C.ACEPTABLE, "Sin urgencia",
                  "Grover lo deja en 128 bits efectivos; suficiente."),
        Algoritmo("CHACHA20", "ChaCha20-Poly1305", C.ACEPTABLE, "Sin urgencia",
                  "Clave de 256 bits: Grover la deja en 128 bits efectivos."),
        Algoritmo("SHA-256", "SHA-256", C.ACEPTABLE, "Sin urgencia",
                  "Grover lo deja en 128 bits efectivos, suficiente hoy; "
                  "sin fecha de caducidad cercana."),
        Algoritmo("SHA-384/512", "SHA-384 / SHA-512", C.ACEPTABLE, "Sin urgencia",
                  "Margen amplio incluso frente a Grover."),
        Algoritmo("TLS-1.2", "TLS 1.2", C.ACEPTABLE,
                  "Sin urgencia; planificar TLS 1.3 (necesario para los "
                  "grupos híbridos con ML-KEM)",
                  "Seguro con cifrados AEAD."),
        Algoritmo("TLS-1.3", "TLS 1.3", C.ACEPTABLE, "Sin urgencia",
                  "Versión actual del protocolo."),
        # 🔵 Post-cuántico
        Algoritmo("ML-KEM", "ML-KEM (Kyber)", C.POST_CUANTICO, "Ya migrado",
                  "Estándar NIST FIPS 203."),
        Algoritmo("ML-KEM-HIBRIDO", "ML-KEM híbrido", C.POST_CUANTICO, "Ya migrado",
                  "Intercambio híbrido clásico + ML-KEM (FIPS 203): sigue "
                  "protegido aunque Shor rompa la parte clásica."),
        Algoritmo("SNTRUP-HIBRIDO", "sntrup761 + X25519 híbrido", C.POST_CUANTICO,
                  "Ya migrado; cuando esté disponible, preferir "
                  "mlkem768x25519-sha256 (estándar NIST)",
                  "Híbrido Streamlined NTRU Prime + X25519."),
        Algoritmo("ML-DSA", "ML-DSA (Dilithium)", C.POST_CUANTICO, "Ya migrado",
                  "Estándar NIST FIPS 204."),
        Algoritmo("SLH-DSA", "SLH-DSA (SPHINCS+)", C.POST_CUANTICO, "Ya migrado",
                  "Estándar NIST FIPS 205."),
        # Casos especiales de WireGuard (ver parsers/vpn.py)
        Algoritmo("WG-SIN-PSK", "WireGuard Curve25519 sin PresharedKey", C.CRITICO,
                  "Añadir PresharedKey a este peer como mitigación; seguir la "
                  "evolución de WireGuard post-cuántico (p. ej. Rosenpass)",
                  "El handshake depende solo de Curve25519, roto por Shor: el "
                  "tráfico capturado hoy podría descifrarse cuando exista un "
                  "ordenador cuántico (cosechar ahora, descifrar después)."),
        Algoritmo("WG-CON-PSK", "WireGuard Curve25519 + PresharedKey", C.ADVERTENCIA,
                  "Rotar la PresharedKey periódicamente y distribuirla por un "
                  "canal seguro; sigue sin ser post-cuántico de verdad",
                  "La PresharedKey mezcla una clave simétrica en el handshake: "
                  "aunque Shor rompa Curve25519, sin la PSK no se pueden derivar "
                  "las claves de sesión, lo que mitiga bastante 'cosechar ahora, "
                  "descifrar después'. No lo convierte en post-cuántico: la "
                  "protección depende de que la PSK se genere, distribuya y "
                  "rote de forma segura."),
    ]
}

# Modificador de modo: se aplica sobre el cifrado base, no es un algoritmo.
MODO_CBC = Algoritmo(
    "CBC", "modo CBC", C.OBSOLETO,
    "Usar AES-256-GCM, AES-256-CTR o ChaCha20-Poly1305",
    "El modo CBC es vulnerable a ataques de oráculo de relleno (tipo Lucky13), "
    "independientemente del cifrado base.",
)
_CIFRADOS_DE_BLOQUE = {"AES-128", "AES-192", "AES-256", "3DES"}


# ---------------------------------------------------------------------------
# Patrones de detección (el orden importa)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Patron:
    regex: re.Pattern[str]
    ids: tuple[str, ...]
    exclusivo: bool = False


def _p(regex: str, *ids: str, exclusivo: bool = False) -> Patron:
    return Patron(re.compile(regex), ids, exclusivo)


PATRONES: list[Patron] = [
    # 1. Híbridos post-cuánticos: primero y exclusivos. Si el nombre completo
    #    es un híbrido conocido no se buscan substrings sueltos (x25519, ecdh...).
    _p(r"mlkem\d+x25519|x25519mlkem\d+|secp\d+r1mlkem\d+|mlkem\d+nistp\d+"
       r"|x25519kyber\d+\w*", "ML-KEM-HIBRIDO", exclusivo=True),
    _p(r"sntrup\d+x25519", "SNTRUP-HIBRIDO", exclusivo=True),
    # 2. Post-cuánticos puros
    _p(r"ml-?kem\d*|kyber\d*", "ML-KEM"),
    _p(r"ml-?dsa(-\d+)?|dilithium\d*", "ML-DSA"),
    _p(r"slh-?dsa[\w-]*|sphincs\S*", "SLH-DSA"),
    # 3. Nombres que implican dos algoritmos: ssh-rsa firma con SHA-1
    _p(r"^ssh-rsa(-cert-v01@openssh\.com)?$", "RSA", "SHA-1"),
    # 4. Asimétricos clásicos (Shor). ECDSA/ECDH antes que DSA/DH.
    _p(r"ecdsa(-sha2-nistp\d+)?|ed(25519|448)", "ECDSA"),
    _p(r"ecdhe?(-sha2-nistp\d+)?|curve(25519|448)|x(25519|448)|(?<![a-z])ecp\d+(bp)?"
       r"|secp\d+[rk]1|prime256v1|nistp\d+|brainpoolp\d+\w*", "ECDH"),
    _p(r"ssh-dss|(?<![a-z])dss(?![a-z])|(?<![a-z])dsa(?![a-z])", "DSA"),
    _p(r"rsa", "RSA"),
    _p(r"diffie-hellman(-group\d+|-group-exchange)?|ffdhe\d+|modp\d+"
       r"|(?<![a-z])e?dhe?(?![a-z])", "DH"),
    # 5. Cifrados simétricos
    _p(r"3des|des-?cbc3|des-ede3|tripledes|(?<![a-z0-9])des(?![a-z0-9])", "3DES"),
    _p(r"rc4|arcfour\d*", "RC4"),
    _p(r"aes[-_]?256", "AES-256"),
    _p(r"aes[-_]?192", "AES-192"),
    # "aes" sin tamaño (IPsec, alias OpenSSL como AESGCM) incluye AES-128
    _p(r"aes[-_]?128|aes(?![-_]?\d)", "AES-128"),
    _p(r"chacha20", "CHACHA20"),
    # 6. Hash
    _p(r"md5", "MD5"),
    _p(r"sha2?[-_]?(512|384)", "SHA-384/512"),
    _p(r"sha2?[-_]?256", "SHA-256"),
    # sufijo "-SHA" de los nombres OpenSSL (AES128-SHA) = HMAC-SHA1
    _p(r"sha-?1(?!\d)|(?<![a-z0-9])sha(?![a-z0-9])", "SHA-1"),
]

_PROTOCOLOS = {
    "sslv2": "SSL",
    "sslv3": "SSL",
    "tlsv1": "TLS-1.0/1.1",
    "tlsv1.0": "TLS-1.0/1.1",
    "tlsv1.1": "TLS-1.0/1.1",
    "tlsv1.2": "TLS-1.2",
    "tlsv1.3": "TLS-1.3",
}


def normalizar(token: str) -> str:
    """Minúsculas, sin comillas ni prefijos de lista (+, ^) ni sufijo estricto (!)."""
    return token.strip().strip("'\"").lower().lstrip("+^").rstrip("!")


def clasificar(token: str, cbc_implicito: bool = False) -> list[Algoritmo]:
    """Devuelve los algoritmos presentes en un nombre, en orden de aparición.

    ``cbc_implicito`` indica que el nombre usa CBC aunque no lo diga (los
    nombres OpenSSL de TLS sin GCM/CCM, como ``AES128-SHA256``).
    """
    t = normalizar(token)
    ocupado: list[tuple[int, int]] = []
    encontrados: list[tuple[int, Algoritmo]] = []
    for patron in PATRONES:
        for m in patron.regex.finditer(t):
            if any(m.start() < fin and ini < m.end() for ini, fin in ocupado):
                continue
            if patron.exclusivo:
                return [ALGORITMOS[i] for i in patron.ids]
            ocupado.append(m.span())
            encontrados.extend((m.start(), ALGORITMOS[i]) for i in patron.ids)
    encontrados.sort(key=lambda e: e[0])
    algoritmos = [a for _, a in encontrados]
    if cbc_implicito or "cbc" in t:
        algoritmos = [_en_modo_cbc(a) if a.id in _CIFRADOS_DE_BLOQUE else a
                      for a in algoritmos]
    return algoritmos


def _en_modo_cbc(base: Algoritmo) -> Algoritmo:
    return replace(
        base,
        id=f"{base.id}-CBC",
        nombre=f"{base.nombre} en {MODO_CBC.nombre}",
        categoria=MODO_CBC.categoria,
        recomendacion=MODO_CBC.recomendacion,
        motivo=MODO_CBC.motivo,
    )


def clasificar_protocolo(version: str) -> Algoritmo | None:
    """Clasifica una versión de protocolo TLS/SSL (``TLSv1.2``, ``SSLv3``...)."""
    id_ = _PROTOCOLOS.get(normalizar(version))
    return ALGORITMOS[id_] if id_ else None

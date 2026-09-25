"""Cliente, Servidor y Atacante del intercambio híbrido X25519 + ML-KEM-768.

Entre actores solo viajan bytes (los mensajes de red); cada actor reconstruye
las claves públicas a partir de ellos, como ocurriría en un protocolo real.
Cada actor anota en un registro compartido lo que genera, para mostrarlo paso
a paso.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

from .cripto import derivar_clave_final


@dataclass(frozen=True)
class Evento:
    actor: str
    elemento: str
    datos: bytes
    viaja_por_la_red: bool = False


# --- Mensajes de red (lo único que ve el Atacante) -------------------------------
@dataclass(frozen=True)
class ClavesPublicasServidor:
    """Servidor → Cliente."""
    x25519: bytes
    mlkem768: bytes


@dataclass(frozen=True)
class RespuestaCliente:
    """Cliente → Servidor."""
    x25519: bytes
    mlkem768_ciphertext: bytes


# --- Actores ---------------------------------------------------------------------
class Actor:
    nombre = "Actor"

    def __init__(self, registro: list[Evento] | None = None):
        self.registro = registro if registro is not None else []

    def _anotar(self, elemento: str, datos: bytes, red: bool = False) -> bytes:
        self.registro.append(Evento(self.nombre, elemento, datos, red))
        return datos


class Servidor(Actor):
    nombre = "Servidor"

    def __init__(self, registro: list[Evento] | None = None):
        super().__init__(registro)
        self._x25519 = x25519.X25519PrivateKey.generate()
        self._mlkem = mlkem.MLKEM768PrivateKey.generate()
        self._anotar("Clave privada X25519", self._x25519.private_bytes_raw())
        self._anotar("Clave pública X25519", self._x25519.public_key().public_bytes_raw())
        self._anotar("Clave privada ML-KEM-768 (semilla)", self._mlkem.private_bytes_raw())
        self._anotar("Clave pública ML-KEM-768", self._mlkem.public_key().public_bytes_raw())
        self.secreto_x25519: bytes | None = None
        self.secreto_mlkem: bytes | None = None
        self.clave_final: bytes | None = None

    def claves_publicas(self) -> ClavesPublicasServidor:
        mensaje = ClavesPublicasServidor(
            x25519=self._x25519.public_key().public_bytes_raw(),
            mlkem768=self._mlkem.public_key().public_bytes_raw(),
        )
        self._anotar("→ envía clave pública X25519", mensaje.x25519, red=True)
        self._anotar("→ envía clave pública ML-KEM-768", mensaje.mlkem768, red=True)
        return mensaje

    def recibir(self, respuesta: RespuestaCliente) -> None:
        """Decapsula el ciphertext y hace X25519 con la pública del Cliente."""
        self.secreto_mlkem = self._anotar(
            "Secreto ML-KEM (decapsulado)",
            self._mlkem.decapsulate(respuesta.mlkem768_ciphertext))
        publica_cliente = x25519.X25519PublicKey.from_public_bytes(respuesta.x25519)
        self.secreto_x25519 = self._anotar(
            "Secreto X25519", self._x25519.exchange(publica_cliente))

    def derivar(self) -> bytes:
        self.clave_final = self._anotar(
            "Clave final (HKDF-SHA384)",
            derivar_clave_final(secreto_mlkem=self.secreto_mlkem,
                                secreto_x25519=self.secreto_x25519))
        return self.clave_final


class Cliente(Actor):
    nombre = "Cliente"

    def __init__(self, registro: list[Evento] | None = None):
        super().__init__(registro)
        self._x25519 = x25519.X25519PrivateKey.generate()
        self._anotar("Clave privada X25519", self._x25519.private_bytes_raw())
        self._anotar("Clave pública X25519", self._x25519.public_key().public_bytes_raw())
        self.secreto_x25519: bytes | None = None
        self.secreto_mlkem: bytes | None = None
        self.clave_final: bytes | None = None

    def responder(self, claves: ClavesPublicasServidor) -> RespuestaCliente:
        """Encapsula contra la pública ML-KEM y hace X25519 con la del Servidor."""
        publica_mlkem = mlkem.MLKEM768PublicKey.from_public_bytes(claves.mlkem768)
        secreto, ciphertext = publica_mlkem.encapsulate()
        self.secreto_mlkem = self._anotar("Secreto ML-KEM (encapsulado)", secreto)
        self._anotar("Ciphertext ML-KEM-768", ciphertext)
        publica_servidor = x25519.X25519PublicKey.from_public_bytes(claves.x25519)
        self.secreto_x25519 = self._anotar(
            "Secreto X25519", self._x25519.exchange(publica_servidor))

        respuesta = RespuestaCliente(
            x25519=self._x25519.public_key().public_bytes_raw(),
            mlkem768_ciphertext=ciphertext,
        )
        self._anotar("→ envía clave pública X25519", respuesta.x25519, red=True)
        self._anotar("→ envía ciphertext ML-KEM-768", ciphertext, red=True)
        return respuesta

    def derivar(self) -> bytes:
        self.clave_final = self._anotar(
            "Clave final (HKDF-SHA384)",
            derivar_clave_final(secreto_mlkem=self.secreto_mlkem,
                                secreto_x25519=self.secreto_x25519))
        return self.clave_final


@dataclass(frozen=True)
class Intento:
    estrategia: str
    clave: bytes


class Atacante(Actor):
    """Solo ve los mensajes de red; nunca tiene acceso a claves privadas."""

    nombre = "Atacante"

    def __init__(self, registro: list[Evento] | None = None):
        super().__init__(registro)
        self.servidor: ClavesPublicasServidor | None = None
        self.cliente: RespuestaCliente | None = None

    def observar(self, servidor: ClavesPublicasServidor,
                 cliente: RespuestaCliente) -> None:
        self.servidor, self.cliente = servidor, cliente

    def intentar(self) -> list[Intento]:
        """Las mejores jugadas posibles sin claves privadas; todas fallan."""
        # 1. Usar claves propias. X25519 exige una privada que case con alguna
        #    de las públicas; ML-KEM con otra privada no da error sino un
        #    secreto pseudoaleatorio distinto (rechazo implícito).
        propia_x = x25519.X25519PrivateKey.generate()
        propia_kem = mlkem.MLKEM768PrivateKey.generate()
        secreto_x = propia_x.exchange(
            x25519.X25519PublicKey.from_public_bytes(self.servidor.x25519))
        secreto_kem = propia_kem.decapsulate(self.cliente.mlkem768_ciphertext)
        self._anotar("Secreto X25519 (con su propia privada)", secreto_x)
        self._anotar("Secreto ML-KEM (decapsulado con su propia privada)", secreto_kem)
        con_claves_propias = self._anotar(
            "Clave final intentada",
            derivar_clave_final(secreto_mlkem=secreto_kem, secreto_x25519=secreto_x))

        # 2. Tratar los datos públicos como si fueran los secretos.
        con_datos_publicos = derivar_clave_final(
            secreto_mlkem=self.cliente.mlkem768_ciphertext[:32],
            secreto_x25519=self.servidor.x25519)

        # 3. Reenviar el ciphertext a un Servidor falso: encapsular de nuevo
        #    contra la pública real solo produce un secreto NUEVO, no el original.
        nuevo_secreto, _ = mlkem.MLKEM768PublicKey.from_public_bytes(
            self.servidor.mlkem768).encapsulate()
        con_reencapsulado = derivar_clave_final(
            secreto_mlkem=nuevo_secreto, secreto_x25519=secreto_x)

        return [
            Intento("claves privadas propias", con_claves_propias),
            Intento("datos públicos como secretos", con_datos_publicos),
            Intento("re-encapsular contra la pública del Servidor", con_reencapsulado),
        ]

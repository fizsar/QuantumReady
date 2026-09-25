import pytest

from quantum_ready.reglas import Categoria, clasificar, clasificar_protocolo
from quantum_ready.riesgo import calcular, nivel_de

C = Categoria


def ids(token, **kw):
    return [a.id for a in clasificar(token, **kw)]


# --- Híbridos antes que substrings sueltos -------------------------------------
@pytest.mark.parametrize("token", [
    "mlkem768x25519-sha256",
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "X25519Kyber768Draft00",
])
def test_hibridos_mlkem_son_post_cuanticos_y_no_se_marcan_como_ecdh(token):
    assert ids(token) == ["ML-KEM-HIBRIDO"]
    assert clasificar(token)[0].categoria is C.POST_CUANTICO


def test_sntrup_hibrido():
    assert ids("sntrup761x25519-sha512@openssh.com") == ["SNTRUP-HIBRIDO"]


def test_x25519_suelto_es_critico():
    assert ids("X25519") == ["ECDH"]
    assert ids("curve25519-sha256") == ["ECDH", "SHA-256"]


# --- Asimétricos -----------------------------------------------------------------
@pytest.mark.parametrize("token, esperado", [
    ("ecdh-sha2-nistp256", ["ECDH"]),
    ("ecdsa-sha2-nistp384", ["ECDSA"]),
    ("ssh-ed25519", ["ECDSA"]),
    ("ssh-dss", ["DSA"]),
    ("ssh_host_dsa_key", ["DSA"]),
    ("ssh_host_ecdsa_key", ["ECDSA"]),
    ("rsa-sha2-512", ["RSA", "SHA-384/512"]),
    ("ssh-rsa", ["RSA", "SHA-1"]),
    ("diffie-hellman-group14-sha1", ["DH", "SHA-1"]),
    ("diffie-hellman-group-exchange-sha256", ["DH", "SHA-256"]),
    ("DHE-RSA-AES256-GCM-SHA384", ["DH", "RSA", "AES-256", "SHA-384/512"]),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", ["ECDH", "ECDSA", "AES-256", "SHA-384/512"]),
    ("modp2048", ["DH"]),
    ("ecp256", ["ECDH"]),
    ("sha256WithRSAEncryption", ["SHA-256", "RSA"]),
])
def test_nombres_compuestos(token, esperado):
    assert ids(token) == esperado


def test_ml_dsa_no_se_confunde_con_dsa():
    assert ids("ml-dsa-65") == ["ML-DSA"]
    assert ids("slh-dsa-sha2-128s") == ["SLH-DSA"]


# --- Categorías corregidas -------------------------------------------------------
@pytest.mark.parametrize("token, categoria", [
    ("hmac-sha1", C.OBSOLETO),
    ("hmac-md5", C.OBSOLETO),
    ("arcfour256", C.OBSOLETO),
    ("hmac-sha2-256", C.ACEPTABLE),
    ("aes192-ctr", C.ACEPTABLE),
    ("aes128-ctr", C.ADVERTENCIA),
    ("aes256-gcm@openssh.com", C.ACEPTABLE),
    ("chacha20-poly1305@openssh.com", C.ACEPTABLE),
    ("ssh-dss", C.CRITICO),
])
def test_categorias(token, categoria):
    assert clasificar(token)[0].categoria is categoria


@pytest.mark.parametrize("version, categoria", [
    ("SSLv3", C.OBSOLETO),
    ("TLSv1", C.OBSOLETO),
    ("TLSv1.1", C.OBSOLETO),
    ("TLSv1.2", C.ACEPTABLE),
    ("TLSv1.3", C.ACEPTABLE),
])
def test_protocolos(version, categoria):
    assert clasificar_protocolo(version).categoria is categoria


# --- Modificador CBC -------------------------------------------------------------
@pytest.mark.parametrize("token", ["aes256-cbc", "aes128-cbc", "TLS_RSA_WITH_AES_256_CBC_SHA256"])
def test_cbc_explicito_es_obsoleto_aunque_el_cifrado_base_sea_aceptable(token):
    cifrado = [a for a in clasificar(token) if a.id.startswith("AES")][0]
    assert cifrado.categoria is C.OBSOLETO
    assert cifrado.id.endswith("-CBC")
    assert "Lucky13" in cifrado.motivo


def test_cbc_implicito_en_nombres_openssl():
    assert "AES-128-CBC" in ids("ECDHE-RSA-AES128-SHA256", cbc_implicito=True)


def test_gcm_y_ctr_no_modifican():
    assert ids("aes256-ctr") == ["AES-256"]
    assert ids("aes256-gcm@openssh.com") == ["AES-256"]


def test_desconocido():
    assert clasificar("umac-128@openssh.com") == []


# --- Riesgo combinado ------------------------------------------------------------
@pytest.mark.parametrize("categoria, exposicion, alcance, puntuacion, nivel", [
    (C.CRITICO, "alta", "alto", 16, "Urgente"),
    (C.CRITICO, "alta", "bajo", 8, "Alto"),
    (C.CRITICO, "baja", "bajo", 4, "Medio"),
    (C.OBSOLETO, "alta", "alto", 12, "Urgente"),
    (C.OBSOLETO, "baja", "bajo", 3, "Bajo"),
    (C.ADVERTENCIA, "alta", "alto", 8, "Alto"),
    (C.ADVERTENCIA, "baja", "bajo", 2, "Bajo"),
    (C.ACEPTABLE, "baja", "bajo", 1, "Bajo"),
    (C.POST_CUANTICO, "alta", "alto", 0, "Ninguno"),
])
def test_riesgo(categoria, exposicion, alcance, puntuacion, nivel):
    r = calcular(categoria, exposicion, alcance)
    assert (r.puntuacion, r.nivel) == (puntuacion, nivel)


@pytest.mark.parametrize("puntuacion, nivel", [
    (0, "Ninguno"), (1, "Bajo"), (3, "Bajo"), (4, "Medio"), (7, "Medio"),
    (8, "Alto"), (11, "Alto"), (12, "Urgente"), (16, "Urgente"),
])
def test_umbrales(puntuacion, nivel):
    assert nivel_de(puntuacion) == nivel

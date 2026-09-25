import datetime
import textwrap
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from quantum_ready.parsers import analizar_archivo, detectar_formato
from quantum_ready.parsers import ssh, tls, vpn


def algoritmos(res):
    return [(d.linea, d.valor, d.algoritmo.id) for d in res.detecciones]


def ids(res):
    return [d.algoritmo.id for d in res.detecciones]


def t(s):
    return textwrap.dedent(s).lstrip("\n")


# --- SSH -------------------------------------------------------------------------
def test_ssh_lista_de_algoritmos_y_hostkeys():
    res = ssh.analizar(Path("sshd_config"), t("""
        # comentario con rsa que no cuenta
        HostKey /etc/ssh/ssh_host_ed25519_key
        KexAlgorithms mlkem768x25519-sha256,ecdh-sha2-nistp256
        Ciphers=aes256-gcm@openssh.com,aes128-cbc
        MACs hmac-sha2-512
        HostKeyAlgorithms ssh-ed25519
    """))
    assert algoritmos(res) == [
        (2, "/etc/ssh/ssh_host_ed25519_key", "ECDSA"),
        (3, "mlkem768x25519-sha256", "ML-KEM-HIBRIDO"),
        (3, "ecdh-sha2-nistp256", "ECDH"),
        (4, "aes256-gcm@openssh.com", "AES-256"),
        (4, "aes128-cbc", "AES-128-CBC"),
        (5, "hmac-sha2-512", "SHA-384/512"),
        (6, "ssh-ed25519", "ECDSA"),
    ]
    assert res.avisos == []


def test_ssh_ignora_eliminaciones_y_avisa_de_valores_por_defecto():
    res = ssh.analizar(Path("sshd_config"), "Ciphers -3des-cbc,+aes256-ctr\n")
    assert ids(res) == ["AES-256"]
    assert any("KexAlgorithms" in a and "por defecto" in a for a in res.avisos)


# --- nginx / Apache --------------------------------------------------------------
def test_nginx():
    res = tls.analizar_nginx(Path("nginx.conf"), t("""
        server {
            ssl_protocols TLSv1.1 TLSv1.3;
            ssl_ciphers 'ECDHE-RSA-AES128-SHA256:!aNULL:HIGH';
            ssl_ecdh_curve X25519MLKEM768:prime256v1;
        }
    """))
    assert ids(res) == ["TLS-1.0/1.1", "TLS-1.3", "ECDH", "RSA", "AES-128-CBC",
                        "SHA-256", "ML-KEM-HIBRIDO", "ECDH"]
    assert any("HIGH" in a for a in res.avisos)


def test_apache_resuelve_all_con_exclusiones():
    res = tls.analizar_apache(Path("ssl.conf"), t("""
        SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
        SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384
    """))
    assert [(d.valor, d.algoritmo.id) for d in res.detecciones] == [
        ("TLSv1.2", "TLS-1.2"),
        ("TLSv1.3", "TLS-1.3"),
        ("TLS_AES_256_GCM_SHA384", "AES-256"),
        ("TLS_AES_256_GCM_SHA384", "SHA-384/512"),
    ]


# --- IPsec -----------------------------------------------------------------------
def test_ipsec_hibrido_no_marca_la_parte_clasica():
    res = vpn.analizar_ipsec(Path("ipsec.conf"), t("""
        conn a
            ike=aes256-sha256-x25519-ke1_mlkem768!
            esp=aes128-sha1-modp2048
            authby=rsasig
        conn b
            authby=psk
    """))
    assert algoritmos(res) == [
        (2, "aes256-sha256-x25519-ke1_mlkem768", "ML-KEM-HIBRIDO"),
        (2, "aes256-sha256-x25519-ke1_mlkem768", "AES-256"),
        (2, "aes256-sha256-x25519-ke1_mlkem768", "SHA-256"),
        (3, "aes128-sha1-modp2048", "AES-128"),
        (3, "aes128-sha1-modp2048", "SHA-1"),
        (3, "aes128-sha1-modp2048", "DH"),
        (4, "rsasig", "RSA"),
    ]


# --- WireGuard -------------------------------------------------------------------
def test_wireguard_psk_por_peer():
    res = vpn.analizar_wireguard(Path("wg0.conf"), t("""
        [Interface]
        PrivateKey = abc=

        [Peer]
        PublicKey = uno=
        PresharedKey = psk=

        [Peer]
        PublicKey = dos=
    """))
    assert [(d.linea, d.algoritmo.id) for d in res.detecciones] == [
        (4, "WG-CON-PSK"), (8, "WG-SIN-PSK")]
    con_psk = res.detecciones[0].algoritmo
    assert con_psk.categoria.value == "advertencia"
    assert "cosechar ahora" in con_psk.motivo


def test_wireguard_sin_peers_avisa():
    res = vpn.analizar_wireguard(Path("wg0.conf"), "[Interface]\nPrivateKey = x\n")
    assert res.detecciones == [] and res.avisos


# --- Certificados ----------------------------------------------------------------
def _cert_pem(clave, hash_):
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "prueba")])
    ahora = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nombre).issuer_name(nombre)
            .public_key(clave.public_key()).serial_number(1)
            .not_valid_before(ahora).not_valid_after(ahora + datetime.timedelta(days=1))
            .sign(clave, hash_))
    return cert.public_bytes(serialization.Encoding.PEM)


def test_certificados_pem_con_varios_bloques(tmp_path):
    pem = (_cert_pem(rsa.generate_private_key(65537, 2048), hashes.SHA256())
           + _cert_pem(ec.generate_private_key(ec.SECP384R1()), hashes.SHA384())
           + _cert_pem(ed25519.Ed25519PrivateKey.generate(), None))
    ruta = tmp_path / "cadena.pem"
    ruta.write_bytes(pem)
    res = analizar_archivo(ruta)
    assert res.formato == "certificado"
    por_bloque = {}
    for d in res.detecciones:
        por_bloque.setdefault(d.linea, []).append((d.directiva, d.algoritmo.id))
    assert list(por_bloque.values()) == [
        [("clave pública", "RSA"), ("firma", "SHA-256"), ("firma", "RSA")],
        [("clave pública", "ECDSA"), ("firma", "ECDSA"), ("firma", "SHA-384/512")],
        [("clave pública", "ECDSA"), ("firma", "ECDSA")],
    ]
    assert "RSA-2048" in res.detecciones[0].valor


def test_certificado_der(tmp_path):
    pem = _cert_pem(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
    der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
    ruta = tmp_path / "c.der"
    ruta.write_bytes(der)
    assert ids(analizar_archivo(ruta)) == ["ECDSA", "ECDSA", "SHA-256"]


def test_certificado_sha1_de_ejemplo():
    res = analizar_archivo(Path(__file__).parent.parent / "ejemplos/web/certs/legado.pem")
    assert "SHA-1" in ids(res)


# --- Detección de formato --------------------------------------------------------
def test_detectar_formato():
    assert detectar_formato(Path("sshd_config")) == "ssh"
    assert detectar_formato(Path("wg0.conf")) == "wireguard"
    assert detectar_formato(Path("x.crt")) == "certificado"
    assert detectar_formato(Path("sitio.conf"), "SSLProtocol all\n") == "apache"
    assert detectar_formato(Path("sitio.conf"), "server {\n ssl_protocols TLSv1.2;\n}") == "nginx"
    assert detectar_formato(Path("x.conf"), "conn a\n ike=aes256\n") == "ipsec"
    assert detectar_formato(Path("notas.txt"), "hola") is None

"""Todos los textos del informe ejecutivo, en castellano y en inglés.

Ningún texto visible del PDF está escrito en el generador ni en la maqueta:
todo sale de aquí. Las dos lenguas deben tener exactamente las mismas claves y
los mismos marcadores ``{...}`` (lo comprueban los tests).

Un valor puede ser una cadena o una tupla (singular, plural) para ``plural()``.
"""

from __future__ import annotations

import string

IDIOMAS = ("es", "en")

# Algoritmos cuyo nombre del libro de reglas (reglas.ALGORITMOS) es técnico y
# vale igual en ambos idiomas. Todo algoritmo que NO esté aquí necesita una
# entrada "tecnico.<id>" en TEXTOS: un test obliga a decidir una de las dos
# cosas para cada algoritmo nuevo, para que ningún nombre en castellano del
# escáner acabe en el informe en inglés.
ALGORITMOS_NEUTROS = frozenset({
    "RSA", "DH", "ECDH", "ECDSA", "DSA", "3DES", "RC4", "MD5", "SHA-1",
    "TLS-1.0/1.1", "SSL", "AES-128", "AES-192", "AES-256", "CHACHA20", "SHA-256",
    "SHA-384/512", "TLS-1.2", "TLS-1.3", "ML-KEM", "ML-DSA", "SLH-DSA",
})

TEXTOS: dict[str, dict[str, str | tuple[str, str]]] = {
    # =========================================================================
    "es": {
        # --- Generales ----------------------------------------------------------
        "titulo": "Informe de Cripto-Agilidad y Preparación Post-Cuántica",
        "pie": "{empresa} · Confidencial · Página {pagina}",
        "meses": "enero,febrero,marzo,abril,mayo,junio,julio,agosto,septiembre,"
                 "octubre,noviembre,diciembre",
        "fecha": "{dia} de {mes} de {anio}",
        "sin_datos": "—",

        # --- Secciones (también son el índice del PDF) --------------------------
        "seccion.portada": "Portada",
        "seccion.resumen": "1. Resumen ejecutivo",
        "seccion.hallazgos": "2. Hallazgos por prioridad",
        "seccion.solucion": "3. La solución propuesta",
        "seccion.coste": "4. Coste de la migración",
        "seccion.pendiente": "5. Qué queda pendiente",
        "seccion.apendice": "6. Apéndice técnico",

        # --- Portada --------------------------------------------------------------
        "portada.subtitulo": "Análisis de la infraestructura y plan de migración "
                             "a criptografía resistente a ordenadores cuánticos",
        "portada.preparado_para": "Preparado para",
        "portada.sector": "Sector",
        "portada.contacto": "Contacto",
        "portada.fecha": "Fecha",
        "portada.confidencial": "Documento confidencial. Contiene detalles de la "
                                "configuración de seguridad de la organización.",

        # --- Niveles --------------------------------------------------------------
        "global.Crítico": "CRÍTICO",
        "global.Alto": "ALTO",
        "global.Medio": "MEDIO",
        "global.Bajo": "BAJO",
        "nivel.Urgente": ("Urgente", "Urgentes"),
        "nivel.Alto": ("Alto", "Altos"),
        "nivel.Medio": ("Medio", "Medios"),
        "nivel.Bajo": ("Bajo", "Bajos"),
        "nivel.Ninguno": ("Ninguno", "Ninguno"),
        "categoria.critico": "Crítico (cuántico)",
        "categoria.obsoleto": "Obsoleto",
        "categoria.advertencia": "Advertencia",
        "categoria.aceptable": "Aceptable",
        "categoria.post_cuantico": "Post-cuántico",

        # --- 1. Resumen ejecutivo --------------------------------------------------
        "resumen.nivel": "Nivel de riesgo global",
        "resumen.conteo": "{urgentes}, {altos}, {total} elementos analizados en "
                          "{servicios} servicios",
        "resumen.regla": "El nivel global sigue la regla del peor caso: lo marca el "
                         "hallazgo más grave, no la media.",
        "resumen.significa.Crítico": "Hay servicios accesibles desde internet, o que "
            "dan acceso a toda la red, protegidos con cifrado que un ordenador "
            "cuántico podrá romper o que ya hoy se considera inseguro. Conviene "
            "actuar en los próximos meses.",
        "resumen.significa.Alto": "Hay servicios importantes con cifrado que un "
            "ordenador cuántico podrá romper. Conviene planificar la migración este año.",
        "resumen.significa.Medio": "Los problemas encontrados afectan a servicios "
            "internos o de alcance limitado. Conviene incluirlos en el plan de "
            "mantenimiento.",
        "resumen.significa.Bajo": "No se han encontrado problemas relevantes en los "
            "servicios analizados.",
        "resumen.solucion": "De los {prioritarios} hallazgos prioritarios (Urgentes y "
            "Altos): {intercambio} se resuelven con el intercambio de claves híbrido "
            "propuesto, {configuracion} se corrigen hoy con cambios de configuración "
            "y {firma} afectan a firmas digitales y dependen de que el ecosistema "
            "post-cuántico madure (sección 5).",
        "resumen.sin_prioritarios": "No hay hallazgos urgentes ni de prioridad alta.",
        "resumen.cifra.intercambio": "se resuelven con el intercambio de claves "
                                     "híbrido",
        "resumen.cifra.configuracion": "se corrigen hoy cambiando la configuración",
        "resumen.cifra.firma": "firmas digitales: pendientes del ecosistema "
                               "post-cuántico",
        "resumen.coste": "Adoptar el intercambio híbrido añade {encuadre} y unos "
                         "{kb} KB de datos por conexión: imperceptible para los "
                         "usuarios.",

        # --- 2. Hallazgos por prioridad -------------------------------------------
        "hallazgos.intro": "Hallazgos con prioridad Urgente o Alta, agrupados por "
            "servicio y problema, de mayor a menor riesgo. La prioridad combina la "
            "gravedad del problema, si el servicio es accesible desde internet y a "
            "cuántos sistemas da acceso.",
        "hallazgos.col.prioridad": "Prioridad",
        "hallazgos.col.servicio": "Servicio",
        "hallazgos.col.que": "Qué ocurre",
        "hallazgos.col.hacer": "Qué hacer",
        "hallazgos.col.casos": "Casos",
        "hallazgos.ninguno": "No hay hallazgos con prioridad Urgente ni Alta.",
        "servicio.tipo.ssh": "Acceso remoto (SSH)",
        "servicio.tipo.tls": "Web / TLS",
        "servicio.tipo.vpn": "VPN",
        "servicio.exposicion.alta": "accesible desde internet",
        "servicio.exposicion.baja": "solo red interna",

        # --- Descripción en lenguaje llano de cada problema ------------------------
        "familia.dh.que": "El acuerdo de claves (Diffie-Hellman) podrá romperse con "
            "un ordenador cuántico: el tráfico grabado hoy podría leerse en el futuro.",
        "familia.ecdh.que": "El acuerdo de claves (curvas elípticas) podrá romperse "
            "con un ordenador cuántico: el tráfico grabado hoy podría leerse en el "
            "futuro.",
        "familia.rsa_intercambio.que": "La clave de sesión se protege con RSA, que un "
            "ordenador cuántico podrá romper: el tráfico grabado hoy podría leerse "
            "en el futuro.",
        "familia.wg_sin_psk.que": "La VPN WireGuard acuerda sus claves solo con "
            "curvas elípticas, que un ordenador cuántico podrá romper.",
        "familia.wg_con_psk.que": "La VPN WireGuard usa una clave compartida extra "
            "que mitiga el riesgo cuántico, pero no lo elimina.",
        "familia.rsa_firma.que": "La identidad del servidor (certificado o clave de "
            "firma) usa RSA, que un ordenador cuántico podrá falsificar.",
        "familia.ecdsa.que": "La identidad del servidor (certificado o clave de "
            "firma) usa curvas elípticas, que un ordenador cuántico podrá falsificar.",
        "familia.dsa.que": "Se admite DSA, un tipo de firma anticuado y además "
            "vulnerable a ordenadores cuánticos.",
        "familia.sha1.que": "Se usa SHA-1, un algoritmo de resumen que ya hoy puede "
            "falsificarse.",
        "familia.md5.que": "Se usa MD5, un algoritmo de resumen roto desde hace años.",
        "familia.3des.que": "Se admite 3DES, un cifrado antiguo y débil.",
        "familia.rc4.que": "Se admite RC4, un cifrado roto y prohibido en TLS.",
        "familia.cbc.que": "Se admite un modo de cifrado (CBC) con ataques conocidos.",
        "familia.tls_antiguo.que": "Se admiten TLS 1.0/1.1, versiones retiradas del "
            "protocolo seguro de la web.",
        "familia.ssl.que": "Se admite SSL, un protocolo roto.",
        "familia.aes128.que": "Se usa AES-128: seguro hoy, pero con poco margen "
            "frente a ordenadores cuánticos.",
        "familia.otro.que": "Configuración criptográfica mejorable: {algoritmo}.",
        "familia.dh.hacer": "Adoptar el intercambio de claves híbrido.",
        "familia.ecdh.hacer": "Adoptar el intercambio de claves híbrido.",
        "familia.rsa_intercambio.hacer": "Adoptar el intercambio de claves híbrido "
                                         "y retirar el transporte de claves RSA.",
        "familia.wg_sin_psk.hacer": "Añadir una clave compartida (PresharedKey) a "
            "este equipo y planificar una VPN post-cuántica.",
        "familia.wg_con_psk.hacer": "Mantener y rotar la clave compartida; planificar "
                                    "una VPN post-cuántica.",
        "familia.rsa_firma.hacer": "Inventariar certificados y claves; migrar a "
            "firmas post-cuánticas cuando los proveedores las soporten.",
        "familia.ecdsa.hacer": "Inventariar certificados y claves; migrar a firmas "
            "post-cuánticas cuando los proveedores las soporten.",
        "familia.dsa.hacer": "Eliminar DSA ya; migrar a firmas post-cuánticas más "
                             "adelante.",
        "familia.sha1.hacer": "Sustituir por SHA-384 o SHA-512.",
        "familia.md5.hacer": "Eliminar y usar SHA-384 o SHA-512.",
        "familia.3des.hacer": "Eliminar y usar AES-256.",
        "familia.rc4.hacer": "Eliminar y usar AES-256 o ChaCha20.",
        "familia.cbc.hacer": "Usar modos modernos (GCM) o ChaCha20.",
        "familia.tls_antiguo.hacer": "Exigir TLS 1.3.",
        "familia.ssl.hacer": "Eliminar SSL y exigir TLS 1.3.",
        "familia.aes128.hacer": "Pasar a AES-256.",
        "familia.otro.hacer": "Revisar con el equipo técnico.",

        # --- 3. La solución propuesta ---------------------------------------------
        "solucion.p1": "Cuando dos equipos se comunican de forma segura, primero "
            "acuerdan una clave secreta que solo ellos conocen y con la que cifran "
            "todo lo demás. Hoy ese acuerdo se basa en problemas matemáticos que un "
            "ordenador cuántico podrá resolver: un atacante que grabe hoy el tráfico "
            "podría descifrarlo dentro de unos años. Es lo que se conoce como "
            "«cosechar ahora, descifrar después».",
        "solucion.p2": "El intercambio de claves híbrido combina el método actual, "
            "probado durante décadas, con uno nuevo diseñado para resistir "
            "ordenadores cuánticos (ML-KEM, estándar del NIST desde 2024). La clave "
            "final depende de los dos a la vez: para obtenerla, un atacante tendría "
            "que romper ambos. Es el mismo mecanismo que ya incorporan los "
            "navegadores y servidores web modernos y OpenSSH, así que no es una "
            "tecnología experimental.",
        "solucion.prueba": "Resultado de la prueba de concepto",
        "solucion.ok_coinciden": "Cliente y servidor obtienen exactamente la misma "
                                 "clave secreta.",
        "solucion.ko_coinciden": "Cliente y servidor NO obtuvieron la misma clave: "
                                 "hay que revisar la prueba.",
        "solucion.ok_atacante": "Un atacante que intercepta toda la comunicación "
                                "falla en sus {n} intentos de obtener la clave.",
        "solucion.ok_atacante_sin_n": "Un atacante que intercepta toda la "
                                      "comunicación no consigue obtener la clave.",
        "solucion.ko_atacante": "El atacante SÍ obtuvo la clave: hay que revisar "
                                "la prueba.",

        # --- 4. Coste de la migración ---------------------------------------------
        "coste.intro": "Se ha medido cuánto tarda en establecerse una conexión "
            "segura con el método actual y con el híbrido, {n} veces en cada tipo "
            "de red, sobre conexiones de red reales con la latencia de cada perfil.",
        "coste.col.red": "Tipo de red",
        "coste.col.actual": "Método actual",
        "coste.col.hibrido": "Híbrido",
        "coste.col.diferencia": "Diferencia",
        "coste.encuadre.todos": "menos de 1 ms por conexión en todos los perfiles "
                                "de red medidos",
        "coste.encuadre.mayoria": "menos de 1 ms por conexión en la mayoría de los "
                                  "perfiles de red medidos ({n} de {total})",
        "coste.encuadre.aprox": "alrededor de {ms} ms por conexión (entre {min} y "
                                "{max} ms según la red)",
        "coste.conclusion": "En resumen, el intercambio híbrido añade {encuadre}.",
        "coste.bytes": "Cada conexión envía {extra} bytes más ({hibrido} frente a "
                       "{actual}): unos {kb} KB, menos que una imagen pequeña.",
        "coste.nota": "Nota: esta medición asume un ancho de banda no limitado. En "
            "redes con ancho de banda restringido, los bytes adicionales se "
            "traducirían en un tiempo extra que no se refleja aquí.",
        "perfil.fibra": "Fibra óptica",
        "perfil.4g": "Móvil 4G",
        "perfil.leo": "Satélite de órbita baja (LEO)",
        "perfil.geo": "Satélite geoestacionario (GEO)",
        "perfil.latencia": "{nombre} ({ms} ms por tramo)",

        # --- 5. Qué queda pendiente ------------------------------------------------
        "pendiente.p1": "El intercambio de claves híbrido protege la "
            "confidencialidad: lo que se transmite hoy no podrá descifrarse mañana. "
            "Pero no resuelve las firmas digitales (certificados y claves que "
            "demuestran la identidad de cada servidor).",
        "pendiente.p2": "Para las firmas ya existen estándares post-cuánticos "
            "(ML-DSA y SLH-DSA), pero las autoridades de certificación, los "
            "navegadores y buena parte del software aún no los admiten de forma "
            "general. La urgencia es menor que en el intercambio de claves: una "
            "firma solo tiene que resistir mientras dura la conexión, así que el "
            "riesgo empieza cuando exista el ordenador cuántico, no antes.",
        "pendiente.firmas": "{n} hallazgos prioritarios corresponden a firmas y "
                            "quedan pendientes de que madure el ecosistema:",
        "pendiente.sin_firmas": "Ningún hallazgo prioritario corresponde a firmas.",
        "pendiente.configuracion": "Además, {n} hallazgos prioritarios no dependen "
            "de la computación cuántica: son configuraciones que ya hoy se "
            "consideran inseguras y se corrigen con cambios de configuración, sin "
            "esperar a nada.",
        "pendiente.col.servicio": "Servicio",
        "pendiente.col.que": "Qué usa",
        "pendiente.col.casos": "Casos",
        "pendiente.pasos": "Próximos pasos recomendados",
        "pendiente.paso1": "Corregir ya las configuraciones obsoletas.",
        "pendiente.paso2": "Desplegar el intercambio de claves híbrido, empezando "
                           "por los servicios accesibles desde internet.",
        "pendiente.paso3": "Inventariar certificados y claves de firma, y seguir la "
                           "adopción de firmas post-cuánticas por los proveedores.",

        # --- 6. Apéndice técnico ----------------------------------------------------
        "apendice.intro": "Datos completos de las tres fases, para el equipo técnico.",
        "apendice.fuentes": "Fuentes de datos",
        "apendice.fuente": "Fase {fase}: {archivo} (generado {fecha})",
        "apendice.fase1": "A.1 Fase 1 — Hallazgos del escáner",
        "apendice.fase1.resumen": "{hallazgos} hallazgos en {archivos} archivos; "
                                  "{sin_evaluar} sin evaluar (fuera del inventario).",
        "apendice.col.riesgo": "Riesgo",
        "apendice.col.categoria": "Categoría",
        "apendice.col.servicio": "Servicio",
        "apendice.col.ubicacion": "Ubicación",
        "apendice.col.algoritmo": "Algoritmo",
        "apendice.col.valor": "Valor",
        "apendice.fase2": "A.2 Fase 2 — Intercambio de claves híbrido",
        "apendice.fase2.esquema": "Esquema: {esquema}",
        "apendice.col.elemento": "Elemento",
        "apendice.col.bytes": "Bytes",
        "apendice.elem.x25519_clave_publica": "Clave pública X25519",
        "apendice.elem.mlkem768_clave_publica": "Clave pública ML-KEM-768",
        "apendice.elem.mlkem768_ciphertext": "Ciphertext ML-KEM-768",
        "apendice.elem.clave_final": "Clave final derivada",
        "apendice.elem.cliente_a_servidor": "Cliente → servidor",
        "apendice.elem.servidor_a_cliente": "Servidor → cliente",
        "apendice.elem.total": "Total en red",
        "apendice.fase3": "A.3 Fase 3 — Impacto en red",
        "apendice.fase3.config": "{n} ejecuciones por celda, {calentamiento} de "
                                 "calentamiento descartadas. Plataforma: {plataforma}.",
        "apendice.col.escenario": "Escenario",
        "apendice.col.red": "Red",
        "apendice.col.media": "Media (ms)",
        "apendice.col.desviacion": "Desv. (ms)",
        "apendice.col.mediana": "Mediana (ms)",
        "apendice.col.min": "Mín. (ms)",
        "apendice.col.max": "Máx. (ms)",
        "escenario.x25519": "X25519 (actual)",
        "escenario.mlkem768": "ML-KEM-768",
        "escenario.hibrido": "Híbrido",
        "tecnico.cbc": "{base} en modo CBC",
        "tecnico.ML-KEM-HIBRIDO": "ML-KEM híbrido",
        "tecnico.SNTRUP-HIBRIDO": "sntrup761 + X25519 híbrido",
        "tecnico.WG-SIN-PSK": "WireGuard Curve25519 sin PresharedKey",
        "tecnico.WG-CON-PSK": "WireGuard Curve25519 + PresharedKey",
        "tecnico.directiva.clave pública": "clave pública",
        "tecnico.directiva.firma": "firma",
        "tecnico.directiva.clave privada": "clave privada",
    },
    # =========================================================================
    "en": {
        "titulo": "Crypto-Agility and Post-Quantum Readiness Report",
        "pie": "{empresa} · Confidential · Page {pagina}",
        "meses": "January,February,March,April,May,June,July,August,September,"
                 "October,November,December",
        "fecha": "{dia} {mes} {anio}",
        "sin_datos": "—",

        "seccion.portada": "Cover",
        "seccion.resumen": "1. Executive summary",
        "seccion.hallazgos": "2. Findings by priority",
        "seccion.solucion": "3. The proposed solution",
        "seccion.coste": "4. Cost of the migration",
        "seccion.pendiente": "5. What remains to be done",
        "seccion.apendice": "6. Technical appendix",

        "portada.subtitulo": "Infrastructure assessment and migration plan to "
                             "quantum-resistant cryptography",
        "portada.preparado_para": "Prepared for",
        "portada.sector": "Sector",
        "portada.contacto": "Contact",
        "portada.fecha": "Date",
        "portada.confidencial": "Confidential document. It contains details of the "
                                "organisation's security configuration.",

        "global.Crítico": "CRITICAL",
        "global.Alto": "HIGH",
        "global.Medio": "MEDIUM",
        "global.Bajo": "LOW",
        "nivel.Urgente": ("Urgent", "Urgent"),
        "nivel.Alto": ("High", "High"),
        "nivel.Medio": ("Medium", "Medium"),
        "nivel.Bajo": ("Low", "Low"),
        "nivel.Ninguno": ("None", "None"),
        "categoria.critico": "Critical (quantum)",
        "categoria.obsoleto": "Obsolete",
        "categoria.advertencia": "Warning",
        "categoria.aceptable": "Acceptable",
        "categoria.post_cuantico": "Post-quantum",

        "resumen.nivel": "Overall risk level",
        "resumen.conteo": "{urgentes}, {altos}, {total} items analysed across "
                          "{servicios} services",
        "resumen.regla": "The overall level follows the worst-case rule: it is set "
                         "by the most serious finding, not by the average.",
        "resumen.significa.Crítico": "Services reachable from the internet, or "
            "giving access to the whole network, are protected with encryption that "
            "a quantum computer will be able to break or that is already considered "
            "unsafe today. Action is advisable within the next few months.",
        "resumen.significa.Alto": "Important services use encryption that a quantum "
            "computer will be able to break. The migration should be planned this "
            "year.",
        "resumen.significa.Medio": "The issues found affect internal or "
            "limited-reach services. They should be included in the maintenance plan.",
        "resumen.significa.Bajo": "No relevant issues were found in the services "
                                  "analysed.",
        "resumen.solucion": "Of the {prioritarios} priority findings (Urgent and "
            "High): {intercambio} are solved by the proposed hybrid key exchange, "
            "{configuracion} can be fixed today with configuration changes, and "
            "{firma} concern digital signatures and depend on the post-quantum "
            "ecosystem maturing (section 5).",
        "resumen.sin_prioritarios": "There are no urgent or high-priority findings.",
        "resumen.cifra.intercambio": "solved by the hybrid key exchange",
        "resumen.cifra.configuracion": "fixed today by changing the configuration",
        "resumen.cifra.firma": "digital signatures: pending on the post-quantum "
                               "ecosystem",
        "resumen.coste": "Adopting the hybrid key exchange adds {encuadre} and about "
                         "{kb} KB of data per connection: unnoticeable for users.",

        "hallazgos.intro": "Findings with Urgent or High priority, grouped by service "
            "and issue, from highest to lowest risk. Priority combines how serious "
            "the issue is, whether the service is reachable from the internet, and "
            "how many systems it gives access to.",
        "hallazgos.col.prioridad": "Priority",
        "hallazgos.col.servicio": "Service",
        "hallazgos.col.que": "What is happening",
        "hallazgos.col.hacer": "What to do",
        "hallazgos.col.casos": "Cases",
        "hallazgos.ninguno": "There are no Urgent or High priority findings.",
        "servicio.tipo.ssh": "Remote access (SSH)",
        "servicio.tipo.tls": "Web / TLS",
        "servicio.tipo.vpn": "VPN",
        "servicio.exposicion.alta": "reachable from the internet",
        "servicio.exposicion.baja": "internal network only",

        "familia.dh.que": "The key agreement (Diffie-Hellman) can be broken by a "
            "quantum computer: traffic recorded today could be read in the future.",
        "familia.ecdh.que": "The key agreement (elliptic curves) can be broken by a "
            "quantum computer: traffic recorded today could be read in the future.",
        "familia.rsa_intercambio.que": "The session key is protected with RSA, which "
            "a quantum computer can break: traffic recorded today could be read in "
            "the future.",
        "familia.wg_sin_psk.que": "The WireGuard VPN agrees its keys using elliptic "
            "curves only, which a quantum computer can break.",
        "familia.wg_con_psk.que": "The WireGuard VPN uses an extra shared key that "
            "mitigates the quantum risk but does not remove it.",
        "familia.rsa_firma.que": "The server's identity (certificate or signing "
            "key) uses RSA, which a quantum computer will be able to forge.",
        "familia.ecdsa.que": "The server's identity (certificate or signing key) "
            "uses elliptic curves, which a quantum computer will be able to forge.",
        "familia.dsa.que": "DSA is allowed: an outdated signature type that is also "
                           "vulnerable to quantum computers.",
        "familia.sha1.que": "SHA-1 is in use: a hash algorithm that can already be "
                            "forged today.",
        "familia.md5.que": "MD5 is in use: a hash algorithm broken for years.",
        "familia.3des.que": "3DES is allowed: an old, weak cipher.",
        "familia.rc4.que": "RC4 is allowed: a broken cipher banned from TLS.",
        "familia.cbc.que": "A cipher mode (CBC) with known attacks is allowed.",
        "familia.tls_antiguo.que": "TLS 1.0/1.1 are allowed: retired versions of "
                                   "the web's security protocol.",
        "familia.ssl.que": "SSL is allowed: a broken protocol.",
        "familia.aes128.que": "AES-128 is in use: safe today, but with little "
                              "margin against quantum computers.",
        "familia.otro.que": "Cryptographic configuration that can be improved: "
                            "{algoritmo}.",
        "familia.dh.hacer": "Adopt the hybrid key exchange.",
        "familia.ecdh.hacer": "Adopt the hybrid key exchange.",
        "familia.rsa_intercambio.hacer": "Adopt the hybrid key exchange and retire "
                                         "RSA key transport.",
        "familia.wg_sin_psk.hacer": "Add a shared key (PresharedKey) to this peer "
                                    "and plan a post-quantum VPN.",
        "familia.wg_con_psk.hacer": "Keep and rotate the shared key; plan a "
                                    "post-quantum VPN.",
        "familia.rsa_firma.hacer": "Inventory certificates and keys; move to "
            "post-quantum signatures once vendors support them.",
        "familia.ecdsa.hacer": "Inventory certificates and keys; move to "
            "post-quantum signatures once vendors support them.",
        "familia.dsa.hacer": "Remove DSA now; move to post-quantum signatures later.",
        "familia.sha1.hacer": "Replace with SHA-384 or SHA-512.",
        "familia.md5.hacer": "Remove and use SHA-384 or SHA-512.",
        "familia.3des.hacer": "Remove and use AES-256.",
        "familia.rc4.hacer": "Remove and use AES-256 or ChaCha20.",
        "familia.cbc.hacer": "Use modern modes (GCM) or ChaCha20.",
        "familia.tls_antiguo.hacer": "Require TLS 1.3.",
        "familia.ssl.hacer": "Remove SSL and require TLS 1.3.",
        "familia.aes128.hacer": "Move to AES-256.",
        "familia.otro.hacer": "Review with the technical team.",

        "solucion.p1": "When two computers communicate securely, they first agree "
            "on a secret key that only they know and use it to encrypt everything "
            "else. Today that agreement relies on mathematical problems that a "
            "quantum computer will be able to solve: an attacker who records the "
            "traffic today could decrypt it in a few years. This is known as "
            "“harvest now, decrypt later”.",
        "solucion.p2": "The hybrid key exchange combines the current method, proven "
            "over decades, with a new one designed to resist quantum computers "
            "(ML-KEM, a NIST standard since 2024). The final key depends on both at "
            "once: to obtain it, an attacker would have to break both. Modern web "
            "browsers and servers and OpenSSH already use this same mechanism, so "
            "it is not an experimental technology.",
        "solucion.prueba": "Proof-of-concept result",
        "solucion.ok_coinciden": "Client and server obtain exactly the same secret "
                                 "key.",
        "solucion.ko_coinciden": "Client and server did NOT obtain the same key: "
                                 "the test must be reviewed.",
        "solucion.ok_atacante": "An attacker who intercepts all the communication "
                                "fails in all {n} attempts to obtain the key.",
        "solucion.ok_atacante_sin_n": "An attacker who intercepts all the "
                                      "communication cannot obtain the key.",
        "solucion.ko_atacante": "The attacker DID obtain the key: the test must be "
                                "reviewed.",

        "coste.intro": "We measured how long it takes to establish a secure "
            "connection with the current method and with the hybrid one, {n} times "
            "for each network type, over real network connections with the latency "
            "of each profile.",
        "coste.col.red": "Network type",
        "coste.col.actual": "Current method",
        "coste.col.hibrido": "Hybrid",
        "coste.col.diferencia": "Difference",
        "coste.encuadre.todos": "less than 1 ms per connection on every network "
                                "profile measured",
        "coste.encuadre.mayoria": "less than 1 ms per connection on most network "
                                  "profiles measured ({n} of {total})",
        "coste.encuadre.aprox": "about {ms} ms per connection (between {min} and "
                                "{max} ms depending on the network)",
        "coste.conclusion": "In short, the hybrid key exchange adds {encuadre}.",
        "coste.bytes": "Each connection sends {extra} more bytes ({hibrido} versus "
                       "{actual}): about {kb} KB, less than a small image.",
        "coste.nota": "Note: this measurement assumes unlimited bandwidth. On "
            "bandwidth-constrained networks, the additional bytes would translate "
            "into extra time that is not captured here.",
        "perfil.fibra": "Fibre optic",
        "perfil.4g": "4G mobile",
        "perfil.leo": "Low Earth orbit satellite (LEO)",
        "perfil.geo": "Geostationary satellite (GEO)",
        "perfil.latencia": "{nombre} ({ms} ms per leg)",

        "pendiente.p1": "The hybrid key exchange protects confidentiality: what is "
            "sent today cannot be decrypted tomorrow. But it does not solve digital "
            "signatures (the certificates and keys that prove each server's "
            "identity).",
        "pendiente.p2": "Post-quantum signature standards already exist (ML-DSA and "
            "SLH-DSA), but certificate authorities, browsers and much of the "
            "software do not support them widely yet. The urgency is lower than for "
            "key exchange: a signature only has to hold while the connection lasts, "
            "so the risk starts when a quantum computer exists, not before.",
        "pendiente.firmas": "{n} priority findings concern signatures and remain "
                            "pending until the ecosystem matures:",
        "pendiente.sin_firmas": "No priority finding concerns signatures.",
        "pendiente.configuracion": "In addition, {n} priority findings have nothing "
            "to do with quantum computing: they are configurations already "
            "considered unsafe today, fixed with configuration changes without "
            "waiting for anything.",
        "pendiente.col.servicio": "Service",
        "pendiente.col.que": "What it uses",
        "pendiente.col.casos": "Cases",
        "pendiente.pasos": "Recommended next steps",
        "pendiente.paso1": "Fix the obsolete configurations now.",
        "pendiente.paso2": "Deploy the hybrid key exchange, starting with the "
                           "services reachable from the internet.",
        "pendiente.paso3": "Inventory certificates and signing keys, and follow "
                           "vendors' adoption of post-quantum signatures.",

        "apendice.intro": "Complete data from the three phases, for the technical "
                          "team.",
        "apendice.fuentes": "Data sources",
        "apendice.fuente": "Phase {fase}: {archivo} (generated {fecha})",
        "apendice.fase1": "A.1 Phase 1 — Scanner findings",
        "apendice.fase1.resumen": "{hallazgos} findings in {archivos} files; "
                                  "{sin_evaluar} unevaluated (outside the inventory).",
        "apendice.col.riesgo": "Risk",
        "apendice.col.categoria": "Category",
        "apendice.col.servicio": "Service",
        "apendice.col.ubicacion": "Location",
        "apendice.col.algoritmo": "Algorithm",
        "apendice.col.valor": "Value",
        "apendice.fase2": "A.2 Phase 2 — Hybrid key exchange",
        "apendice.fase2.esquema": "Scheme: {esquema}",
        "apendice.col.elemento": "Item",
        "apendice.col.bytes": "Bytes",
        "apendice.elem.x25519_clave_publica": "X25519 public key",
        "apendice.elem.mlkem768_clave_publica": "ML-KEM-768 public key",
        "apendice.elem.mlkem768_ciphertext": "ML-KEM-768 ciphertext",
        "apendice.elem.clave_final": "Derived final key",
        "apendice.elem.cliente_a_servidor": "Client → server",
        "apendice.elem.servidor_a_cliente": "Server → client",
        "apendice.elem.total": "Total on the wire",
        "apendice.fase3": "A.3 Phase 3 — Network impact",
        "apendice.fase3.config": "{n} runs per cell, {calentamiento} warm-up runs "
                                 "discarded. Platform: {plataforma}.",
        "apendice.col.escenario": "Scenario",
        "apendice.col.red": "Network",
        "apendice.col.media": "Mean (ms)",
        "apendice.col.desviacion": "Std. dev. (ms)",
        "apendice.col.mediana": "Median (ms)",
        "apendice.col.min": "Min (ms)",
        "apendice.col.max": "Max (ms)",
        "escenario.x25519": "X25519 (current)",
        "escenario.mlkem768": "ML-KEM-768",
        "escenario.hibrido": "Hybrid",
        "tecnico.cbc": "{base} in CBC mode",
        "tecnico.ML-KEM-HIBRIDO": "ML-KEM hybrid",
        "tecnico.SNTRUP-HIBRIDO": "sntrup761 + X25519 hybrid",
        "tecnico.WG-SIN-PSK": "WireGuard Curve25519 without PresharedKey",
        "tecnico.WG-CON-PSK": "WireGuard Curve25519 + PresharedKey",
        "tecnico.directiva.clave pública": "public key",
        "tecnico.directiva.firma": "signature",
        "tecnico.directiva.clave privada": "private key",
    },
}


def marcadores(valor: str | tuple[str, str]) -> set[str]:
    """Nombres de los ``{marcadores}`` de un texto (o de ambas formas de una tupla)."""
    textos = valor if isinstance(valor, tuple) else (valor,)
    return {campo for t in textos for _, campo, _, _ in string.Formatter().parse(t)
            if campo}


class Traductor:
    """Acceso a los textos de un idioma: ``t("clave", marcador=valor)``."""

    def __init__(self, idioma: str):
        if idioma not in IDIOMAS:
            raise ValueError(f"Idioma no soportado: {idioma} (usa {', '.join(IDIOMAS)})")
        self.idioma = idioma
        self._textos = TEXTOS[idioma]

    def __call__(self, clave: str, **valores) -> str:
        texto = self._textos[clave]
        if isinstance(texto, tuple):
            texto = texto[0]
        return texto.format(**valores) if valores else texto

    def existe(self, clave: str) -> bool:
        return clave in self._textos

    def plural(self, clave: str, n: int) -> str:
        """``"3 Urgentes"`` / ``"1 Urgente"``."""
        singular, plural = self._textos[clave]
        return f"{n} {singular if n == 1 else plural}"

    def numero(self, valor: float, decimales: int = 2) -> str:
        texto = f"{valor:.{decimales}f}"
        return texto.replace(".", ",") if self.idioma == "es" else texto

    def fecha(self, dia, mes: int, anio: int) -> str:
        meses = self("meses").split(",")
        return self("fecha", dia=dia, mes=meses[mes - 1], anio=anio)

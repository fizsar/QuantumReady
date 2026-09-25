"""Datos de empresa ficticia para el informe cuando no se indican los reales.

Para usar datos reales sin tocar código, pásalos por línea de comandos
(--empresa-nombre, --empresa-sector, --empresa-contacto) o en un YAML con
--empresa (ver ejemplos/empresa.yaml). Un campo puede ser un texto o un
diccionario por idioma ({es: ..., en: ...}).
"""

EMPRESA_EJEMPLO = {
    "nombre": "Ejemplo Energía S.L.",
    "sector": {"es": "Energía y servicios públicos", "en": "Energy and utilities"},
    "contacto": "seguridad@ejemplo-energia.test",
}

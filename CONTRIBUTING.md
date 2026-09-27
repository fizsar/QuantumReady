# Convenciones de desarrollo

**Español** · [English](CONTRIBUTING.en.md) · [← Volver al README](README.md)

Convenciones del proyecto y las lecciones de las que salieron.

## Un fallo en una cadena de comandos debe bloquear el commit

Al encadenar comandos que deben impedir un commit si algo falla (por ejemplo,
ejecutar los tests antes de `git commit`), usa siempre `set -o pipefail` en
bash:

```bash
set -o pipefail
python -m pytest -q 2>&1 | tail -1 && git commit -m "..."
```

Sin `set -o pipefail`, una tubería devuelve el código de salida de su **último**
comando. En `pytest ... | tail -1 && git commit`, ese comando es `tail`, que
casi siempre termina con 0, así que el commit se hace aunque los tests hayan
fallado.

**Cómo se descubrió:** una cadena `pytest -q | tail -1 && git commit` permitió
un commit con un test roto (`1 failed, 392 passed`), porque el código de salida
que llegó al `&&` era el de `tail`, no el de `pytest`. Con la corrección
(`set -o pipefail; pytest -q | tail -1 && git commit`), un commit de prueba en
las mismas condiciones, con un test roto a propósito, quedó bloqueado: la cadena
terminó con código 1 y no se creó ningún commit.

import sys

from .benchmark import main

# Guardia necesaria: el servidor arranca procesos con "spawn", que reimportan
# este módulo.
if __name__ == "__main__":
    sys.exit(main())

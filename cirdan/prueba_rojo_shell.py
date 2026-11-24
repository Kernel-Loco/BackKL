"""PR de prueba de RC-254, no se fusiona: una llamada con shell=True pone seguridad en rojo."""

import subprocess


def correr():
    return subprocess.run("true", shell=True, check=False)

"""Configuración de Cirdan: variables de entorno o, fuera de Docker, el `.env` de la raíz."""
import os
from functools import cache

from cirdan import RAIZ


@cache
def _env_file():
    env = RAIZ / '.env'
    if not env.exists():
        return {}
    return dict(line.split('=', 1) for line in env.read_text().split() if '=' in line)


def config(name, default=None):
    """Valor de una variable: primero el entorno, después el `.env`, después `default`."""
    if name in os.environ:
        return os.environ[name]
    return _env_file().get(name, default)


def required(name):
    value = config(name)
    if not value:
        raise RuntimeError('Falta %s: copia .env.example como .env y llena sus valores' % name)
    return value

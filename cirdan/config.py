"""Configuración de Cirdan: variables de entorno o, fuera de Docker, el `.env` de la raíz."""
import os
from functools import cache
from urllib.parse import urlsplit

from cirdan import RAIZ

# Orígenes de la API cuando ALLOWED_ORIGINS no está puesta: el portal y la propia API en la PC de quien desarrolla.
ORIGENES_LOCALES = 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000'


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


def _como_origin(origen):
    """El origen como lo manda el navegador en Origin: esquema y host en minúsculas, sin barra final y sin el puerto
    por omisión (443 en https, 80 en http). Uno con ruta, consulta o sin host se deja tal cual y no coincide nunca."""
    partes = urlsplit(origen.rstrip('/'))
    if not partes.scheme or not partes.netloc or partes.path or partes.query or partes.fragment:
        return origen
    esquema, netloc = partes.scheme.lower(), partes.netloc.lower()
    defecto = {'https': ':443', 'http': ':80'}.get(esquema)
    if defecto and netloc.endswith(defecto):
        netloc = netloc[:-len(defecto)]
    return '%s://%s' % (esquema, netloc)


def origenes_permitidos():
    """Orígenes de `ALLOWED_ORIGINS`, sin espacios ni vacíos y escritos como el Origin del navegador. Sin poner o vacía,
    ORIGENES_LOCALES: docker-compose.yml la pasa a la API con `${ALLOWED_ORIGINS:-}`, y con '' la API rechazaría toda
    escritura con Origin (comentario 10401 de RC-277). El candado de las cuentas de demo (cirdan/auth/demo.py) toma
    igual la vacía, pero no normaliza: ahí un origen con mayúsculas cuenta como publicado. La usan el filtro de Origin (cirdan/api/main.py), las passkeys y la regla de RC-286."""
    declarados = [_como_origin(o.strip()) for o in (config('ALLOWED_ORIGINS') or '').split(',') if o.strip()]
    return declarados or ORIGENES_LOCALES.split(',')


def required(name):
    value = config(name)
    if not value:
        raise RuntimeError('Falta %s: copia .env.example como .env y llena sus valores' % name)
    return value

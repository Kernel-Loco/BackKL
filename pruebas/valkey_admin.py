"""Cliente de Valkey como cirdan_admin para las pruebas que corren dentro del contenedor de la API (RC-292).

cirdan_api, el usuario de la API, solo tiene los comandos y los prefijos de cirdan/auth/sessions.py: sin SCAN, TTL,
HGETALL ni PEXPIRE, que las pruebas usan para revisar llaves. Las funciones de sessions.py siguen yendo con cirdan_api,
así que la prueba también revisa que la API funciona con su lista. La contraseña de cirdan_admin la pasa el comando de
pruebas con `-e VALKEY_ADMIN_PASSWORD` (pruebas.yml y README): la API nunca la recibe en su compose.
"""
import os
from functools import cache
from urllib.parse import quote, urlsplit, urlunsplit

import redis


@cache
def cliente():
    clave = os.environ.get('VALKEY_ADMIN_PASSWORD')
    if not clave:
        raise RuntimeError('Falta VALKEY_ADMIN_PASSWORD: el comando de pruebas la pasa con -e (RC-292)')
    url = urlsplit(os.environ['VALKEY_URL'])
    lugar = url.hostname + (':%d' % url.port if url.port else '')
    url = url._replace(netloc='cirdan_admin:%s@%s' % (quote(clave, safe=''), lugar))
    return redis.Redis.from_url(urlunsplit(url), decode_responses=True, socket_timeout=3, socket_connect_timeout=3)

"""Candado de la pila de desarrollo para las pruebas de base y API (RC-254, control 8.31 de la política).

Las pruebas que entran a la base, a Valkey o a la API escriben en ellas, así que nunca corren contra la pila de
desarrollo (cirdan-pg16, cirdan-valkey, cirdan-api y el puerto 8000), sino contra el compose desechable de
docker-compose.pruebas.yml:
- Desde tu PC, con las variables CIRDAN_TEST_* del paso 5 del README.
- Dentro de un contenedor (/.dockerenv), solo con CIRDAN_TEST_DB_ISOLATED=true, que ponen el compose desechable, el de
  pruebas/enlace/ y el CI. Un `docker compose run api ...` en la pila de desarrollo no la trae y frena.
- En el CI (GITHUB_ACTIONS=true) la pila del runner ya es desechable.
Toda función de pruebas/ que corre `docker exec` llama antes a exigir_desechable() o a exigir_contenedor(), y
pruebas/test_ci.py lo revisa.
"""
import os
from pathlib import Path
from urllib.parse import urlsplit

# Las mismas variables y valores por omisión que sesion.py y test_aislamiento.py
VARIABLES = (('CIRDAN_TEST_DB_CONTAINER', 'cirdan-pg16'), ('CIRDAN_TEST_VALKEY', 'cirdan-valkey'),
             ('CIRDAN_TEST_API_CONTAINER', 'cirdan-api'), ('CIRDAN_TEST_BASE', 'http://127.0.0.1:8000'))
DESARROLLO = {'cirdan-pg16', 'cirdan-valkey', 'cirdan-api'}
AVISO = 'Levanta el compose desechable y exporta las variables del paso 5 del README.'


def de_desarrollo(entorno):
    """Las variables que apuntan a la pila de desarrollo, con su valor."""
    malas = []
    for nombre, omision in VARIABLES:
        valor = (entorno.get(nombre) or omision).strip()
        if nombre == 'CIRDAN_TEST_BASE':
            url = urlsplit(valor)
            if url.hostname in ('127.0.0.1', 'localhost', '::1') and url.port == 8000:
                malas.append('%s=%s' % (nombre, valor))
        elif valor in DESARROLLO:
            malas.append('%s=%s' % (nombre, valor))
    return malas


def _libre(entorno, en_contenedor):
    """True si la pila es desechable sin revisar nombres: el CI, o un contenedor del compose desechable."""
    if entorno.get('GITHUB_ACTIONS') == 'true':
        return True
    if en_contenedor is None:
        en_contenedor = Path('/.dockerenv').exists()
    if en_contenedor:
        if entorno.get('CIRDAN_TEST_DB_ISOLATED') == 'true':
            return True
        raise RuntimeError('Dentro de un contenedor las pruebas de base y API solo corren con '
                           'CIRDAN_TEST_DB_ISOLATED=true, que pone el compose desechable. ' + AVISO)
    return False


def exigir_desechable(entorno=None, en_contenedor=None):
    """Falla si las pruebas apuntan a la pila de desarrollo."""
    entorno = os.environ if entorno is None else entorno
    if _libre(entorno, en_contenedor):
        return
    malas = de_desarrollo(entorno)
    if malas:
        raise RuntimeError('Las pruebas de base y API no corren contra la pila de desarrollo (%s). %s'
                           % (', '.join(malas), AVISO))


def exigir_contenedor(nombre, entorno=None, en_contenedor=None):
    """Falla si `nombre`, un contenedor que la prueba elige con otra variable, es de la pila de desarrollo."""
    entorno = os.environ if entorno is None else entorno
    if _libre(entorno, en_contenedor):
        return
    if (nombre or '').strip() in DESARROLLO:
        raise RuntimeError('Las pruebas no corren contra %s, de la pila de desarrollo. %s' % (nombre, AVISO))

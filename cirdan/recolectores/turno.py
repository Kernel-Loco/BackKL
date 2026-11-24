"""Una petición a la vez por host entre todos los análisis de LowTide (comentario 10281.2 de RC-46).

Las fuentes de un escaneo corren en serie, pero dos escaneos pueden correr a la vez y visitar el mismo host: un
dominio y un subdominio suyo dados de alta aparte (olmardo.com y tienda.olmardo.com), en la misma empresa o en dos, o
un escaneo de la API y uno del programador. Cada petición a un sitio del dominio (visita.ClienteWeb.sitio, que
también usa identidad.py, y api_docs.ClienteApiDocs.ruta) va dentro de turno(host): si otro escaneo tiene una
petición abierta a ese host, espera a que termine.

El candado lo pone el orquestador con con_candado() mientras corre una fuente en vivo o al grabar: es
orquestador._turno_host, un candado de PostgreSQL que vale entre la API y el programador. Sin candado puesto (la
línea de comandos, las pruebas sin base o al reproducir) turno() no espera nada.
"""
from contextlib import contextmanager
from contextvars import ContextVar

from cirdan.recolectores.shodan import SinTiempo

# Lo pone con_candado() en el hilo del escaneo. Un hilo nuevo empieza sin candado.
_CANDADO = ContextVar('turno_host', default=None)


class SinTurno(SinTiempo):
    """No se pudo tomar el turno del host: otro escaneo lo tuvo más tiempo del que le queda a la corrida, o la base
    no respondió. Es un SinTiempo: la petición no sale y lo que falta queda sin revisar, como cuando se acaba la
    corrida. Nunca se pide al sitio sin el turno."""


@contextmanager
def con_candado(candado):
    """Pone `candado(host, espera)` para las peticiones de este hilo mientras dura el bloque. `candado` es un
    administrador de contexto que entra cuando tiene el host para sí y lanza SinTurno si no lo consigue en `espera`
    segundos. Con None, no hay candado."""
    marca = _CANDADO.set(candado)
    try:
        yield
    finally:
        _CANDADO.reset(marca)


@contextmanager
def turno(host, espera):
    """El turno de `host` para una petición, si hay candado puesto, esperando como mucho `espera` segundos."""
    candado = _CANDADO.get()
    if candado is None:
        yield
        return
    with candado((host or '').strip().lower().rstrip('.'), espera):
        yield

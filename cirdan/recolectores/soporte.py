"""Versión sin soporte (outdated_software) con la API abierta de endoflife.date, sin red (#18, RC-46).

No es un recolector y no hace peticiones: la visita web pide a endoflife.date la lista de ciclos de cada producto
(url()) y le pasa la respuesta a revisar() junto con la tecnología que dio huellas.analizar(). Así las pruebas usan
respuestas armadas a mano (pruebas/fixtures/huellas/) y nunca la API.

Cómo decide:
- Solo las tecnologías de PRODUCTOS, con el nombre de Wappalyzer y el producto de endoflife.date. Otra da
  'sin_producto'.
- Solo con versión, de una huella que el sitio mostró (no implicada por otra) y con confianza 100. Sin eso da
  'sin_version'.
- Nunca una versión de una distribución, como 'nginx/1.24.0 (Ubuntu)' (huellas.py, 'distribucion'): la distribución le
  sigue mandando parches que endoflife.date no ve. Da 'distribucion' y ningún hallazgo (_plan de RC-66, etica-1).
- El ciclo es el más largo de endoflife.date que es prefijo de la versión por partes: 1.24.0 cae en 1.24, 7.4.33 en
  7.4 y 3.6.0 en 3. Sin ciclo da 'sin_dato', igual que una respuesta que no se puede leer o un ciclo cuyo eol no se
  puede leer (no cae en un ciclo más corto): no se sabe, nunca 'con soporte'.
- Sin soporte si eol es true o si su fecha ya pasó (`hoy`). Con eol false o una fecha que no ha llegado da
  'con_soporte'.
Lee las dos formas de la API: la v1 (/api/v1/products/<producto>/, con result.releases, isEol y eolFrom) y la de antes
(/api/<producto>.json, una lista con cycle y eol).

El hallazgo no se arma aquí: revisar() da 'hallazgo' con codigo, severidad, clave (el producto: un ciclo nuevo sin
soporte del mismo producto es el mismo hallazgo), titulo y evidencia, y la visita lo pasa a contrato.Hallazgo con su
activo, su huella y la rúbrica.
"""
import re
from datetime import date, datetime

CODIGOS = {'outdated_software': 'high'}   # la severidad del catálogo (semilla 001)
URL_V1 = 'https://endoflife.date/api/v1/products/%s/'
NOMBRE_FUENTE = 'endoflife.date'
MIN_CONFIANZA = 100
TITULO = 'Versión sin soporte: %s %s en %s'

# Nombre de Wappalyzer -> producto de endoflife.date. Solo productos con ciclos numéricos, que se comparan con la
# versión. Los productos no se han consultado en vivo: se revisan con la primera consulta de la visita web.
PRODUCTOS = {'AngularJS': 'angularjs', 'Apache HTTP Server': 'apache-http-server', 'Apache Tomcat': 'tomcat',
             'Django': 'django', 'Drupal': 'drupal', 'Ghost': 'ghost', 'IIS': 'iis', 'Jetty': 'eclipse-jetty',
             'Joomla': 'joomla', 'jQuery': 'jquery', 'Next.js': 'nextjs', 'Nginx': 'nginx', 'PHP': 'php',
             'Perl': 'perl', 'Python': 'python', 'React': 'react', 'Umbraco': 'umbraco', 'Vue.js': 'vue',
             'WordPress': 'wordpress'}
ESTADOS = ('sin_soporte', 'con_soporte', 'sin_dato', 'distribucion', 'sin_version', 'sin_producto')

_PRODUCTO = re.compile(r'[a-z0-9][a-z0-9-]{0,62}')
_VERSION = re.compile(r'[0-9]+(?:\.[0-9]+){0,5}')   # la parte numérica de la versión: 1.24.0, 8.1.2 o 3
_CICLO = re.compile(r'[0-9]+(?:\.[0-9]+){0,5}')
_FECHA = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')


def url(producto):
    """La URL de la API v1 de endoflife.date para `producto`, o None si no es un nombre de producto."""
    return URL_V1 % producto if isinstance(producto, str) and _PRODUCTO.fullmatch(producto) else None


def _fecha(x):
    if isinstance(x, str) and _FECHA.fullmatch(x):
        try:
            return date.fromisoformat(x)
        except ValueError:
            return None
    return None


def ciclos(respuesta):
    """[{'ciclo', 'eol': True, False, una fecha o None, 'ultima'}] de la respuesta de la API v1 o de la de antes. Un
    ciclo que no es numérico se salta. Uno sin eol legible queda con eol None, para que la versión no caiga en un
    ciclo más corto que sí se lee (revisar() da 'sin_dato'). None si la respuesta no se puede leer."""
    if isinstance(respuesta, dict) and isinstance(respuesta.get('result'), dict):
        filas, v1 = respuesta['result'].get('releases'), True
    elif isinstance(respuesta, list):
        filas, v1 = respuesta, False
    else:
        return None
    if not isinstance(filas, list):
        return None
    salida = []
    for f in filas:
        if not isinstance(f, dict):
            continue
        nombre = f.get('name') if v1 else f.get('cycle')
        nombre = str(nombre) if isinstance(nombre, (str, int)) and not isinstance(nombre, bool) else ''
        if not _CICLO.fullmatch(nombre):
            continue
        if v1:
            fin = _fecha(f.get('eolFrom'))
            eol = fin if fin else f.get('isEol') if isinstance(f.get('isEol'), bool) else None
            ultima = f.get('latest', {}).get('name') if isinstance(f.get('latest'), dict) else None
        else:
            eol = f.get('eol') if isinstance(f.get('eol'), bool) else _fecha(f.get('eol'))
            ultima = f.get('latest')
        salida.append({'ciclo': nombre, 'eol': eol, 'ultima': ultima if isinstance(ultima, str) else None})
    return salida


def ciclo_de(version, lista):
    """El ciclo más largo de `lista` que es prefijo de la versión por partes, o None."""
    m = _VERSION.match(version) if isinstance(version, str) else None
    if not m:
        return None
    partes = m.group(0).split('.')
    mejor = None
    for c in lista or ():
        cp = c['ciclo'].split('.')
        if partes[:len(cp)] == cp and (mejor is None or len(cp) > len(mejor['ciclo'].split('.'))):
            mejor = c
    return mejor


def _hoy(hoy):
    if isinstance(hoy, datetime):
        return hoy.date()
    return hoy if isinstance(hoy, date) else date.today()


def revisar(tecnologia, respuesta, host, hoy=None):
    """{'estado' (de ESTADOS), 'producto', 'ciclo', 'hallazgo' (o None)} de una tecnología de huellas.analizar()
    con la respuesta de endoflife.date de su producto. Solo 'sin_soporte' trae hallazgo."""
    t = tecnologia if isinstance(tecnologia, dict) else {}
    producto = PRODUCTOS.get(t.get('nombre'))
    salida = {'estado': 'sin_producto', 'producto': producto, 'ciclo': None, 'hallazgo': None}
    if not producto:
        return salida
    version = t.get('version')
    if not isinstance(version, str) or not _VERSION.match(version) or t.get('implicada_por') \
            or not isinstance(t.get('confianza'), int) or t['confianza'] < MIN_CONFIANZA:
        return dict(salida, estado='sin_version')
    if t.get('distribucion'):
        return dict(salida, estado='distribucion')
    ciclo = ciclo_de(version, ciclos(respuesta))
    if not ciclo:
        return dict(salida, estado='sin_dato')
    eol = ciclo['eol']
    if eol is None:   # el ciclo de la versión existe pero su fin no se puede leer: no se sabe
        return dict(salida, estado='sin_dato', ciclo=ciclo['ciclo'])
    hoy = _hoy(hoy)
    sin_soporte = eol is True or (isinstance(eol, date) and eol <= hoy)
    salida = dict(salida, ciclo=ciclo['ciclo'], estado='sin_soporte' if sin_soporte else 'con_soporte')
    if not sin_soporte:
        return salida
    titulo = TITULO % (t['nombre'], version, host)
    evidencia = {'title': titulo, 'tecnologia': t['nombre'], 'version': version, 'producto': producto,
                 'ciclo': ciclo['ciclo'], 'fin_de_soporte': eol.isoformat() if isinstance(eol, date) else None,
                 'ultima_del_ciclo': ciclo['ultima'], 'senales': list(t.get('senales') or []),
                 'fuente_datos': NOMBRE_FUENTE, 'url_fuente': url(producto), 'host': host}
    salida['hallazgo'] = {'codigo': 'outdated_software', 'severidad': CODIGOS['outdated_software'],
                          'clave': producto, 'titulo': titulo, 'evidencia': evidencia}
    return salida

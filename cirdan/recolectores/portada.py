"""Listado de directorio y página de depuración en la portada (#111, RC-228).

Lee la misma respuesta que la visita web (visita.py) ya bajó para huellas.py, sin ninguna petición nueva: la página
principal de cada sitio, también la de un 4xx o un 5xx, que transporte.visitar() lee con el mismo tope que una 200.

Las firmas son la lista corta FIRMAS, versionada aquí (VERSION). Solo miran tres zonas del principio de la página:
- titulo: el texto del primer <title> que no está dentro de un <svg>.
- encabezado: el texto del primer <h1> a <h6>.
- inicio: el texto con que empieza la respuesta antes de cualquier documento HTML (antes del primer <!doctype>, <html>,
  <head>, <body>, <title>, <meta>, <link>, <script>, <style>, <div> o <p>). Es el encabezado de PHP, que escribe su
  error al principio, sin título ni encabezado, con sus propias etiquetas <br>, <b>, <font> o <table>, que se quitan.
Las zonas se sacan con un lector lineal de marcas y no con html.parser, que tarda de forma cuadrática con muchas
etiquetas sin cerrar (como dice huellas.py). Salta comentarios, <script> y <style>, y cada marca tiene un tope.
El resto del cuerpo no se lee: un blog que dice 'Index of /' o 'Fatal error' en su texto no da hallazgo.

Fuera de esta lista: la página por omisión de nginx, Apache o IIS (señal débil) y los secretos del JavaScript del sitio
(cambia la carta).
"""
import html
import re

VERSION = 1

CODIGOS = {'directory_listing': 'medium', 'debug_page_exposed': 'high'}
CWE = {'directory_listing': 'CWE-548', 'debug_page_exposed': 'CWE-215'}

MAX_LEIDO = 64 * 1024   # caracteres del principio del cuerpo donde se buscan las tres zonas
MAX_ZONA = 4000         # caracteres de cada zona: lo que sigue no se lee. Alcanza para el mensaje largo de un error
                        # con su SQL antes de la marca del final de Werkzeug o Symfony
MAX_TITULO = 120        # caracteres del título de la página en la evidencia

# (id, código, servidor, zona, patrón). Zonas: 'titulo', 'encabezado', 'titulo_o_encabezado', 'iguales' (el título y
# el encabezado dicen lo mismo y eso cumple el patrón) e 'inicio'. Cada patrón va anclado y se compara con la zona ya
# sin espacios de más. 'salvo_titulo' quita la firma si el título cumple ese otro patrón. 'contiene' pide además que
# ese otro patrón salga en algún lugar de la zona.
FIRMAS = (
    # Apache (mod_autoindex), nginx (autoindex) y lighttpd escriben 'Index of /ruta' en el título y en el <h1>.
    {'id': 'index_of', 'codigo': 'directory_listing', 'servidor': 'Apache, nginx o lighttpd',
     'zona': 'titulo_o_encabezado', 'patron': r'Index of /[^<>]*'},
    # IIS (directoryBrowse) escribe 'nombre - /ruta' en el título y en el <h1>. '[To Parent Directory]' es el primer
    # enlace del listado y no sale en la raíz, que es lo que se visita: por eso la firma mira el título y el <h1>.
    {'id': 'iis_listado', 'codigo': 'directory_listing', 'servidor': 'IIS',
     'zona': 'iguales', 'patron': r'[A-Za-z0-9.-]+ - /[^<>]*'},
    # Django con DEBUG = True: 'Excepcion at /ruta' en el 500 y 'Page not found at /ruta' en el 404.
    {'id': 'django', 'codigo': 'debug_page_exposed', 'servidor': 'Django',
     'zona': 'titulo', 'patron': r'(?:[A-Za-z_][A-Za-z0-9_]*|Page not found) at /\S*'},
    {'id': 'werkzeug', 'codigo': 'debug_page_exposed', 'servidor': 'Werkzeug',
     'zona': 'titulo', 'patron': r'.* // Werkzeug Debugger'},
    {'id': 'laravel_whoops', 'codigo': 'debug_page_exposed', 'servidor': 'Laravel (Whoops)',
     'zona': 'titulo', 'patron': r'Whoops! There was an error\.'},
    {'id': 'laravel_ignition', 'codigo': 'debug_page_exposed', 'servidor': 'Laravel (Ignition)',
     'zona': 'titulo', 'patron': '\U0001f9e8 .+'},
    # Symfony en modo debug: 'mensaje (500 Internal Server Error)'. Su página de producción dice 'An Error Occurred'.
    {'id': 'symfony', 'codigo': 'debug_page_exposed', 'servidor': 'Symfony',
     'zona': 'titulo', 'patron': r".+ \([45][0-9]{2} [A-Z][A-Za-z' -]+\)"},
    # ASP.NET con customErrors en Off: el <h1> 'Server Error in '/' Application.' y en el título el mensaje del error.
    # Con customErrors en RemoteOnly el título es 'Runtime Error' y la página no trae la traza.
    {'id': 'aspnet', 'codigo': 'debug_page_exposed', 'servidor': 'ASP.NET',
     'zona': 'encabezado', 'patron': r"Server Error in '[^']*' Application\.?", 'salvo_titulo': r'Runtime Error'},
    # PHP con display_errors: 'Fatal error: ... in /ruta/archivo.php on line 12' o '... archivo.php:12'. Con
    # html_errors el error va en <b>Fatal error</b>: y al quitar las etiquetas queda un espacio antes de los dos puntos.
    # Antes del Fatal error puede haber avisos (Warning, Notice, Deprecated), como el require de un vendor/ que falta.
    {'id': 'php', 'codigo': 'debug_page_exposed', 'servidor': 'PHP', 'zona': 'inicio',
     'patron': r'(?:\(\s*!\s*\)\s*)?(?:PHP\s+)?(?:Fatal error|Parse error|Warning|Notice|Deprecated|Strict Standards)'
               r'\s*:\s.*',
     'contiene': r'(?:Fatal|Parse) error\s*:\s.*?(?:\son line\s+[0-9]+|\.php:[0-9]+)\b'},
)
_PATRONES = {f['id']: re.compile(f['patron'], re.S) for f in FIRMAS}
_SALVO = {f['id']: re.compile(f['salvo_titulo']) for f in FIRMAS if 'salvo_titulo' in f}
_CONTIENE = {f['id']: re.compile(f['contiene'], re.S) for f in FIRMAS if 'contiene' in f}

_FIN_DEL_INICIO = re.compile(r'<(?:!doctype|html|head|body|title|meta|link|script|style|div|p)\b', re.I)
# Cada marca con un tope de 500 caracteres hasta su '>': sin tope, muchas '<' sin cerrar vuelven cuadrática la búsqueda
_ETIQUETA = re.compile(r'<[^<>]{0,500}>')
_MARCA = re.compile(r'<(?:(!--)|(/?)(svg|title|h[1-6]|script|style)\b[^<>]{0,500}>)', re.I)
_CIERRE_CRUDO = {n: re.compile(r'</%s\s*>' % n, re.I) for n in ('script', 'style')}
_ESPACIOS = re.compile(r'\s+')
# Lo que contrato.validar y la base no aceptan (el nulo y un surrogate suelto), el resto de los de control y el BOM.
# Es una tabla de str.translate y no una clase de regex: CodeQL marcaba el tramo de \x0e a \x1f (alerta 8, RC-347).
_CONTROL = dict.fromkeys(
    (*range(0x00, 0x09), 0x0b, 0x0c, *range(0x0e, 0x20), 0x7f, 0xfeff, *range(0xd800, 0xe000)), ' ')
# Lo que no va en la evidencia aunque salga en el título. El mensaje de un error puede traer la cadena de conexión:
# - de una URL, todo lo que va de '//' al último '@' (la contraseña puede traer '/' o '@'), y un 'usuario:contraseña'
#   que quedó sin su '@' al cortar la zona.
# - el valor de un Bearer, Basic, Digest o Token.
# - el valor de toda clave con pass, pwd, secret, token, key, auth, credential, cookie o session, con '=', ':', '=>' o
#   su forma codificada (%3D, %3A), entre comillas o no, también en JSON ("password": "x"). Quitar de más es mejor que
#   dejar un secreto.
_URL_CON_USUARIO = re.compile(r'(//)\S*@')
_URL_CORTADA = re.compile(r'(//)[^\s/@]*:[^\s@]*$')
_AUTORIZACION = re.compile(r'\b(Bearer|Basic|Digest|Token)\s+[^\s,;)]+', re.I)
_VALOR_SECRETO = re.compile(
    r'''(\w{0,30}(?:pass|pwd|secret|token|key|auth|credential|cookie|session)\w{0,30}["']?\s*(?:=>|=|:|%3D|%3A)\s*)'''
    r'''(?:"[^"]*"?|'[^']*'?|[^\s,;)&"']+)''', re.I)
_MARCAS_HTML = re.compile('[<>]')


def _limpio(texto):
    return _ESPACIOS.sub(' ', texto.translate(_CONTROL)).strip()[:MAX_ZONA]


def _texto_de(cuerpo, desde, hasta):
    return _limpio(html.unescape(_ETIQUETA.sub(' ', cuerpo[desde:min(hasta, desde + MAX_ZONA * 4)])))


def zonas(cuerpo):
    """{'titulo', 'encabezado', 'inicio'} del principio de `cuerpo`, cada una de a lo más MAX_ZONA caracteres ('' si
    no está). Nunca lanza por el HTML: lo que no se puede leer queda vacío. Tarda lo lineal en el largo del cuerpo."""
    cuerpo = cuerpo[:MAX_LEIDO] if isinstance(cuerpo, str) else ''
    hallado = {'titulo': None, 'encabezado': None}
    svg, abierta, pos = 0, None, 0
    while hallado['titulo'] is None or hallado['encabezado'] is None:
        m = _MARCA.search(cuerpo, pos)
        if not m:
            break
        pos = m.end()
        if m.group(1):   # un comentario: se salta entero
            fin = cuerpo.find('-->', pos)
            if fin < 0:
                break
            pos = fin + 3
            continue
        cierre, nombre = m.group(2) == '/', m.group(3).lower()
        if abierta:      # se lee un título o un encabezado: solo cuenta su cierre
            zona, etiqueta, desde = abierta
            if cierre and nombre == etiqueta:
                hallado[zona], abierta = _texto_de(cuerpo, desde, m.start()), None
            continue
        if nombre in _CIERRE_CRUDO:   # el código de un <script> o un <style> no es texto de la página
            if not cierre:
                fin = _CIERRE_CRUDO[nombre].search(cuerpo, pos)
                if not fin:
                    break
                pos = fin.end()
        elif nombre == 'svg':
            if cierre:
                svg = max(0, svg - 1)
            elif not m.group(0).endswith('/>'):
                svg += 1
        elif cierre:
            continue
        elif nombre == 'title':
            if hallado['titulo'] is None and not svg:
                abierta = ('titulo', 'title', pos)
        elif hallado['encabezado'] is None:
            abierta = ('encabezado', nombre, pos)
    fin = _FIN_DEL_INICIO.search(cuerpo, 0, MAX_ZONA * 8)
    inicio = cuerpo[:fin.start() if fin else MAX_ZONA * 8]
    return {'titulo': hallado['titulo'] or '', 'encabezado': hallado['encabezado'] or '',
            'inicio': _limpio(html.unescape(_ETIQUETA.sub(' ', inicio)))}


def _cumple(firma, z):
    patron = _PATRONES[firma['id']]
    zona = firma['zona']
    if zona == 'titulo_o_encabezado':
        return bool(patron.fullmatch(z['titulo']) or patron.fullmatch(z['encabezado']))
    if zona == 'iguales':
        return bool(z['titulo']) and z['titulo'] == z['encabezado'] and bool(patron.fullmatch(z['titulo']))
    if not patron.fullmatch(z[zona]):
        return False
    contiene = _CONTIENE.get(firma['id'])
    if contiene and not contiene.search(z[zona]):
        return False
    salvo = _SALVO.get(firma['id'])
    return not (salvo and salvo.fullmatch(z['titulo']))


def sin_secretos(texto):
    """El texto sin el usuario y la contraseña de una URL, sin el valor de un Bearer ni el de una clave de secreto
    (password=, token=, "secret": ..., api_key%3D...)."""
    texto = _URL_CORTADA.sub(r'\1***', _URL_CON_USUARIO.sub(r'\1***@', texto))
    return _VALOR_SECRETO.sub(r'\1***', _AUTORIZACION.sub(r'\1 ***', texto))


def titulo_seguro(titulo):
    """El título para la evidencia: sin secretos, sin '<' ni '>' (nunca HTML) y de a lo más MAX_TITULO caracteres."""
    return _MARCAS_HTML.sub('', sin_secretos(titulo))[:MAX_TITULO].strip()


def revisar(estado, cuerpo):
    """[{codigo, firma, servidor, titulo_pagina}] de la página: a lo más uno por código, el de la primera firma de
    FIRMAS que coincide. El listado de directorio solo cuenta en una respuesta 2xx. La página de depuración en
    cualquier estado: suele llegar con un 500 o un 404."""
    z = zonas(cuerpo)
    vistos = {}
    for firma in FIRMAS:
        if firma['codigo'] in vistos:
            continue
        if firma['codigo'] == 'directory_listing' and not (isinstance(estado, int) and 200 <= estado < 300):
            continue
        if _cumple(firma, z):
            vistos[firma['codigo']] = {'codigo': firma['codigo'], 'firma': firma['id'], 'servidor': firma['servidor'],
                                       'titulo_pagina': titulo_seguro(z['titulo'])}
    return list(vistos.values())

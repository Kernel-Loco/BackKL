"""Tecnologías web de un sitio por cabeceras y huellas, sin red (#18, RC-46).

No es un recolector (no está en REGISTRO ni tiene MAX_CONSULTAS): como borde.py, son funciones puras para la visita
web normal de la actividad 6 del Anexo A, que las llama con la respuesta que ya tiene de cada sitio. No hace ninguna
petición ni consulta DNS, y no tiene código de regla: soporte.py (outdated_software) y nvd.py (known_vulnerability)
leen lo que da analizar().

Huellas. huellas_wappalyzer.json sale de Wappalyzer 6.10.54 de npm (15 ene 2023), la última versión con licencia MIT:
desde la 6.10.55 es GPL-3.0 y desde la 7.0 es privada. Las huellas actuales de wappalyzergo no sirven: su
fingerprints_data.json se arma con webappanalyzer y HTTPArchive/wappalyzer, que son GPL-3.0. El archivo trae solo las
categorías del Hecho cuando (CATEGORIAS: CMS, frameworks de JavaScript y web, servidores web, lenguajes y librerías de
JavaScript) y solo los campos que se leen de una sola respuesta (CAMPOS): js, dom, xhr, dns, css, robots, url, text y
certIssuer piden un navegador o consultas aparte y no se usan. Se genera con

    python -m cirdan.recolectores.huellas <ruta de wappalyzer-6.10.54.tgz>

que lee el tarball sin extraerlo ni ejecutar nada, revisa su nombre, versión, licencia e integridad (sha512 de npm) y
escribe el archivo. La procedencia y el aviso MIT van en el archivo y en NOTICE.

Motor. Sigue el formato de Wappalyzer (wappalyzer.js del mismo paquete): cada patrón es una regex sin distinguir
mayúsculas con '\\;version:\\1' (también el ternario '\\1?a:b') y '\\;confidence:50', y cuentan implies, excludes y
requires. Las regex de JavaScript se pasan a Python al cargar (_regex): + y * llevan el tope de 250 de Wappalyzer, se
comparan solo en ASCII (re.ASCII, como borde.py) y un patrón que Python no compila no entra al archivo
(filtro.patrones_descartados). Se lee:
- headers: las cabeceras de la respuesta, salvo las que borde.por_cabeceras() atribuye al CDN o WAF (por ejemplo
  'server: cloudflare'): esas son del borde y no del sitio.
- cookies: el nombre y el valor de cada Set-Cookie, salvo las del borde. De una cookie solo sale su nombre en
  'senales', nunca su valor.
- meta (name o property y content), scriptSrc (el src de cada <script>), scripts (el texto de cada <script> del HTML,
  y el de los scripts que pase la visita) y html (el cuerpo).
Topes: MAX_HTML del cuerpo, MAX_VALOR por cabecera (el de borde._pares), MAX_SCRIPTS y MAX_SCRIPT, y TOPE_SEGUNDOS
para todo el análisis. re de Python no corta una regex a la mitad: el tope de tiempo se revisa entre un patrón y el
siguiente, y si se pasa el análisis queda incompleto ('completo': False) con lo que ya salió. Por eso + y * llevan
tope de 250, como en Wappalyzer, y también {n,}; y el html se recorta donde las regex '<[^>]{1,250}' pasarían de
MAX_COSTO_HTML (_recortar_html), que también deja el análisis incompleto. Una respuesta armada para trabar las regex
no pasa de TOPE_SEGUNDOS más un patrón (pruebas/test_huellas.py).

Reto. Si borde.reto() dice que la respuesta es un reto o un bloqueo del WAF, no se analiza: 'tecnologias' es None,
que quiere decir sin cobertura, nunca 0 tecnologías, y la visita pone el sitio en sin_revisar con borde.aviso().

Distribución. Una versión de la misma cabecera que trae la marca de una distribución, como 'nginx/1.24.0 (Ubuntu)' o
'PHP/8.1.2-1ubuntu2.14', o de una cabecera server o x-powered-by de una respuesta que en alguna de esas dos trae la
marca, como 'Apache/2.4.6 (CentOS)' con 'X-Powered-By: PHP/5.4.16', lleva 'distribucion': la distribución le sigue
mandando parches que endoflife.date y la NVD no ven (_plan de RC-66, etica-1), así que soporte.py y nvd.py no la
marcan. Una versión del HTML (por ejemplo el generator de WordPress) no la lleva: esa no la actualiza la distribución.
"""
import base64
import functools
import hashlib
import html as html_lib
import json
import re
import sys
import tarfile
import time
from pathlib import Path

from cirdan.recolectores import borde

ARCHIVO = Path(__file__).resolve().parent / 'huellas_wappalyzer.json'

# Lo que se espera del tarball de npm. La integridad es la del registro de npm (dist.integrity y dist.shasum).
PAQUETE = {'nombre': 'wappalyzer', 'version': '6.10.54', 'licencia': 'MIT', 'autor': 'Wappalyzer',
           'repositorio': 'https://github.com/wappalyzer/wappalyzer',
           'tarball': 'https://registry.npmjs.org/wappalyzer/-/wappalyzer-6.10.54.tgz',
           'integridad': 'sha512-P9VSYXSL6hiExangdWwipDlmMEdpdPqeHuv4QqsUTVxhuj4ua1YrE4xL7ENxs9b2wk9'
                         'JeIzFR+ZqTmrlSYSEgw==',
           'shasum': 'de8e0f0386f66bc6ce858408de9faa477f304c5e', 'bytes': 337360}
# Categorías del Hecho cuando, con el id y el nombre de categories.json.
CATEGORIAS = {1: 'CMS', 12: 'JavaScript frameworks', 18: 'Web frameworks', 22: 'Web servers',
              27: 'Programming languages', 59: 'JavaScript libraries'}
CAMPOS = ('cookies', 'headers', 'html', 'meta', 'scriptSrc', 'scripts')    # los que se leen de una respuesta
RELACIONES = ('excludes', 'implies', 'requires', 'requiresCategory')
CON_LLAVE = ('cookies', 'headers', 'meta')                                  # {nombre: patrones}

MAX_HTML = 256 * 1024        # caracteres del cuerpo que se analizan
MAX_VALOR = borde.MAX_VALOR  # de cada cabecera, ya cortada en borde._pares
MAX_SCRIPTS = 200            # <script src> y <meta> que se leen del HTML
MAX_SRC = 2 * 1024           # caracteres de cada src y de cada content de <meta>
MAX_ETIQUETA = 4 * 1024      # caracteres que se buscan hasta el '>' de un <script> o <meta>
MAX_SCRIPT = 64 * 1024       # caracteres de cada script que se analizan
MAX_TEXTO_SCRIPTS = 256 * 1024   # entre todos los scripts
MAX_COSTO_HTML = 1000000     # pasos de las regex '<[^>]{1,250}...' en el html (_recortar_html)
TOPE_SEGUNDOS = 3.0          # para todo el análisis, revisado entre patrones
CUANTIFICADOR = 250          # el tope de + y * de Wappalyzer (parsePattern)
MAX_LARGO_VERSION = 15       # Wappalyzer descarta versiones más largas (resolve)

# Marca de una distribución en el valor de una cabecera: entre paréntesis o en el sufijo de la versión del paquete.
DISTRIBUCIONES = (('Ubuntu', r'ubuntu'), ('Debian', r'debian|[+~.-]deb\d'), ('CentOS', r'centos'),
                  ('Red Hat', r'red ?hat|\brhel'), ('Fedora', r'fedora|[.-]fc\d+\b'),
                  ('Amazon Linux', r'amazon ?linux|[.-]amzn\d*\b'), ('Rocky Linux', r'rocky'),
                  ('AlmaLinux', r'alma ?linux'), ('Oracle Linux', r'oracle ?linux'), ('SUSE', r'suse|\bsles'),
                  ('Raspbian', r'raspbian'), ('Alpine', r'alpine'),
                  ('Enterprise Linux', r'[.-]el\d+(?:_\d+)?\b'))
CABECERAS_DEL_SERVIDOR = ('server', 'x-powered-by')

_DISTROS = [(n, re.compile(p, re.I | re.A)) for n, p in DISTRIBUCIONES]
_SEPARA_COOKIES = re.compile(r',\s*(?=[^;,=\s]+=)')   # Set-Cookie juntadas con ', ', sin partir un Expires


# ---------------------------------------------------------------- de JavaScript a Python

def _regex(js):
    """La regex de Wappalyzer en Python: + y * fuera de una clase llevan el tope de 250 (parsePattern), y también
    {n,}, que Wappalyzer deja sin tope y con un valor armado tarda el cuadrado de su largo. '(?<nombre>'
    pasa a '(?P<nombre>' y se compila con re.I y re.A. Lanza re.error si Python no la acepta (por ejemplo un lookbehind
    de largo variable)."""
    salida, i, clase = [], 0, False
    while i < len(js):
        c = js[i]
        if c == '\\' and i + 1 < len(js):
            salida.append(js[i:i + 2])
            i += 2
            continue
        if clase:
            clase = c != ']'
        elif c == '[':
            clase = True
        elif c == '+':
            c = '{1,%d}' % CUANTIFICADOR
        elif c == '*':
            c = '{0,%d}' % CUANTIFICADOR
        elif c == '{' and re.match(r'\{\d{1,4},\}', js[i:]):   # {2,} también lleva tope
            n = re.match(r'\{(\d{1,4}),\}', js[i:])
            salida.append('{%s,%d}' % (n.group(1), max(int(n.group(1)), CUANTIFICADOR)))
            i += len(n.group(0))
            continue
        elif c == '(' and js.startswith('(?<', i) and i + 3 < len(js) and js[i + 3] not in '=!':
            c = '(?P'
            salida.append(c)
            i += 2
            continue
        salida.append(c)
        i += 1
    return re.compile(''.join(salida), re.I | re.A)


def _patron(texto):
    """(regex, versión, confianza) de un patrón 'regex\\;version:\\1\\;confidence:50' (parsePattern)."""
    partes = str(texto).split('\\;')
    atributos = {}
    for parte in partes[1:]:
        llave, _, valor = parte.partition(':')
        if _:
            atributos[llave] = valor
    try:
        confianza = int(atributos.get('confidence') or 100)
    except ValueError:
        confianza = 100
    return _regex(partes[0]), atributos.get('version', ''), confianza


def _lista(x):
    if x is None:
        return []
    return list(x) if isinstance(x, list) else [x]


# ---------------------------------------------------------------- filtro del tarball

def _tecnologia(datos, nombre, descartados):
    """La tecnología con solo CAMPOS, RELACIONES, cats y cpe, sin los patrones que Python no compila."""
    t = {'cats': sorted(c for c in datos.get('cats', []) if c in CATEGORIAS)}
    if datos.get('cpe'):
        t['cpe'] = datos['cpe']
    for campo in CAMPOS:
        if campo not in datos:
            continue
        valor = datos[campo]
        grupos = valor.items() if isinstance(valor, dict) else [(None, valor)]
        limpio = {}
        for llave, patrones in grupos:
            buenos = []
            for p in _lista(patrones):
                try:
                    _patron(p)
                    buenos.append(p)
                except re.error as e:
                    descartados.append({'tecnologia': nombre, 'campo': campo, 'patron': str(p), 'error': str(e)})
            if buenos:
                limpio[llave] = buenos[0] if len(buenos) == 1 and not isinstance(patrones, list) else buenos
        if limpio:
            t[campo] = limpio[None] if None in limpio else limpio
    for campo in RELACIONES:
        if campo in datos:
            t[campo] = _lista(datos[campo])
    return t


def filtrar(tecnologias, categorias):
    """(tecnologías, patrones descartados) con solo CATEGORIAS: las que tienen algún patrón de CAMPOS y las que ellas
    implican dentro de esas categorías. implies, excludes y requires solo nombran tecnologías que quedan, y una que
    requiere una tecnología o una categoría que no quedó sale (Wappalyzer nunca la analizaría)."""
    for c, nombre in CATEGORIAS.items():
        if categorias.get(str(c), {}).get('name') != nombre:
            raise ValueError('categories.json no trae la categoría %d %r' % (c, nombre))
    descartados = []
    elegidas = {n: _tecnologia(d, n, descartados) for n, d in sorted(tecnologias.items())
                if set(d.get('cats', [])) & set(CATEGORIAS)}
    quedan = {n for n, t in elegidas.items() if any(c in t for c in CAMPOS)}
    while True:   # las implicadas por las que quedan, y lo que esas implican
        nuevas = {i.split('\\;')[0] for n in quedan for i in elegidas[n].get('implies', [])} & set(elegidas) - quedan
        if not nuevas:
            break
        quedan |= nuevas
    while True:   # sin requires a lo que no quedó
        fuera = {n for n in quedan if any(r not in quedan for r in elegidas[n].get('requires', []))
                 or any(int(c) not in CATEGORIAS for c in elegidas[n].get('requiresCategory', []))}
        if not fuera:
            break
        quedan -= fuera
    salida = {}
    for n in sorted(quedan):
        t = elegidas[n]
        for campo in ('implies', 'excludes'):
            if campo in t:
                t[campo] = [i for i in t[campo] if i.split('\\;')[0] in quedan]
                if not t[campo]:
                    del t[campo]
        salida[n] = t
    return salida, [d for d in descartados if d['tecnologia'] in quedan]


def generar(ruta_tgz):
    """El contenido de huellas_wappalyzer.json desde el tarball de npm, sin extraerlo ni ejecutar nada. Lanza
    ValueError si el tarball no es el de PAQUETE."""
    crudo = Path(ruta_tgz).read_bytes()
    integridad = 'sha512-' + base64.b64encode(hashlib.sha512(crudo).digest()).decode('ascii')
    if (integridad, hashlib.sha1(crudo).hexdigest(), len(crudo)) != (
            PAQUETE['integridad'], PAQUETE['shasum'], PAQUETE['bytes']):
        raise ValueError('el tarball no es el de %s %s de npm' % (PAQUETE['nombre'], PAQUETE['version']))
    tecnologias, categorias, paquete = {}, None, None
    with tarfile.open(ruta_tgz, 'r:gz') as tar:
        for m in tar.getmembers():
            if not m.isfile():
                continue
            if re.fullmatch(r'package/technologies/[_a-z]\.json', m.name):
                tecnologias.update(json.load(tar.extractfile(m)))
            elif m.name == 'package/categories.json':
                categorias = json.load(tar.extractfile(m))
            elif m.name == 'package/package.json':
                paquete = json.load(tar.extractfile(m))
    if not paquete or (paquete.get('name'), paquete.get('version'), paquete.get('license'), paquete.get('author')) != (
            PAQUETE['nombre'], PAQUETE['version'], PAQUETE['licencia'], PAQUETE['autor']):
        raise ValueError('package.json no dice %s %s con licencia %s' % (
            PAQUETE['nombre'], PAQUETE['version'], PAQUETE['licencia']))
    elegidas, descartados = filtrar(tecnologias, categorias or {})
    procedencia = dict(PAQUETE, tecnologias_en_paquete=len(tecnologias), categorias_en_paquete=len(categorias))
    return {'procedencia': procedencia,
            'filtro': {'categorias': {str(c): n for c, n in CATEGORIAS.items()}, 'campos': list(CAMPOS),
                       'relaciones': list(RELACIONES), 'tecnologias': len(elegidas),
                       'con_cpe': sum(1 for t in elegidas.values() if 'cpe' in t),
                       'patrones_descartados': descartados},
            'tecnologias': elegidas}


def serializar(datos):
    """JSON estable, con una tecnología por línea para que un cambio se lea en el diff."""
    def uno(x):
        return json.dumps(x, ensure_ascii=False, sort_keys=True)
    lineas = ['{', '"procedencia": %s,' % uno(datos['procedencia']), '"filtro": %s,' % uno(datos['filtro']),
              '"tecnologias": {']
    nombres = sorted(datos['tecnologias'])
    lineas += ['%s: %s%s' % (uno(n), uno(datos['tecnologias'][n]), ',' if i < len(nombres) - 1 else '')
               for i, n in enumerate(nombres)]
    return '\n'.join(lineas + ['}', '}']) + '\n'


# ---------------------------------------------------------------- carga

@functools.lru_cache(maxsize=4)
def cargar(ruta=ARCHIVO):
    """{'procedencia', 'tecnologias': {nombre: {'cats', 'cpe', 'patrones': {campo: [(llave, regex, versión,
    confianza)]}, 'implies': [(nombre, versión, confianza)], 'excludes', 'requires', 'requiresCategory'}}}. Lanza
    re.error si un patrón no compila: el archivo solo trae los que sí."""
    datos = json.loads(Path(ruta).read_text(encoding='utf-8'))
    salida = {}
    for nombre, t in datos['tecnologias'].items():
        patrones = {}
        for campo in CAMPOS:
            valor = t.get(campo)
            if valor is None:
                continue
            grupos = valor.items() if isinstance(valor, dict) else [(None, valor)]
            patrones[campo] = [((llave.lower() if llave is not None else None),) + _patron(p)
                               for llave, ps in grupos for p in _lista(ps)]
        implica = []
        for i in t.get('implies', []):
            partes = i.split('\\;')
            atributos = dict(p.partition(':')[::2] for p in partes[1:])
            try:
                confianza = int(atributos.get('confidence') or 100)
            except ValueError:
                confianza = 100
            implica.append((partes[0], atributos.get('version', ''), confianza))
        salida[nombre] = {'cats': t.get('cats', []), 'cpe': t.get('cpe'), 'patrones': patrones, 'implies': implica,
                          'excludes': t.get('excludes', []), 'requires': t.get('requires', []),
                          'requiresCategory': [int(c) for c in t.get('requiresCategory', [])]}
    return {'procedencia': datos['procedencia'], 'tecnologias': salida}


# ---------------------------------------------------------------- lo que se lee de la respuesta

_ETIQUETA = re.compile(r'<(?:(script|meta)(?=[\s/>])|!--)', re.I | re.A)
_ATRIBUTO = re.compile(r'''([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?''', re.A)
_FIN_SCRIPT = re.compile(r'</script\s*>', re.I | re.A)


def _atributos(texto):
    """{nombre en minúsculas: valor} de los atributos de una etiqueta, con las entidades ya cambiadas."""
    salida = {}
    for m in _ATRIBUTO.finditer(texto):
        valor = next((v for v in m.group(2, 3, 4) if v is not None), None)
        if valor is not None:
            salida.setdefault(m.group(1).translate(borde._MINUSCULAS), html_lib.unescape(valor))
    return salida


class _Html:
    """meta (name o property -> [content]), src de cada <script> y texto de cada <script>, con sus topes. No usa
    html.parser: con muchas etiquetas sin '>' vuelve a leer hasta el final desde cada una y tarda minutos. Aquí cada
    etiqueta se busca a lo más MAX_ETIQUETA caracteres y el texto avanza siempre, así que es lineal."""

    def __init__(self, html):
        self.meta, self.script_src, self.scripts = {}, [], []
        metas, total, p = 0, 0, 0
        while True:
            m = _ETIQUETA.search(html, p)
            if not m:
                return
            if m.group(1) is None:   # <!-- ... -->
                fin = html.find('-->', m.end())
                p = len(html) if fin < 0 else fin + 3
                continue
            fin = html.find('>', m.end(), m.end() + MAX_ETIQUETA)
            if fin < 0:
                p = m.end()
                continue
            a = _atributos(html[m.end():fin])
            p = fin + 1
            if m.group(1).lower() == 'meta':
                llave = a.get('name') or a.get('property')
                if llave and 'content' in a and metas < MAX_SCRIPTS:
                    metas += 1
                    self.meta.setdefault(llave.translate(borde._MINUSCULAS), []).append(a['content'][:MAX_SRC])
                continue
            src = a.get('src', '').strip()
            if src and not src.startswith('data:text/javascript;') and len(self.script_src) < MAX_SCRIPTS:
                self.script_src.append(src[:MAX_SRC])
            cierre = _FIN_SCRIPT.search(html, p)
            texto = html[p:cierre.start() if cierre else len(html)][:MAX_SCRIPT]
            p = cierre.end() if cierre else len(html)
            if texto.strip() and total < MAX_TEXTO_SCRIPTS and len(self.scripts) < MAX_SCRIPTS:
                self.scripts.append(texto[:MAX_TEXTO_SCRIPTS - total])
                total += len(self.scripts[-1])


def _html(cuerpo):
    """Los primeros MAX_HTML caracteres del cuerpo. Bytes se leen como UTF-8 y lo ilegible se cambia."""
    if isinstance(cuerpo, (bytes, bytearray)):
        cuerpo = bytes(cuerpo[:MAX_HTML * 4]).decode('utf-8', errors='replace')
    return cuerpo[:MAX_HTML] if isinstance(cuerpo, str) else ''


def _recortar_html(html):
    """(html, recortado): el html hasta donde las regex de Wappalyzer que empiezan con '<[^>]{1,250}' (unas 200)
    caben en MAX_COSTO_HTML. Cada '<' les cuesta hasta el siguiente '>', con tope de 250: una página real de 256 KiB
    cuesta unos 200 mil y una armada de puros '<', 65 millones (31 s). Lo que queda fuera no se revisa con las regex
    del html, pero sí con el lector de <meta> y <script>."""
    costo, fin = 0, -1
    p = html.find('<')
    while p >= 0:
        if fin < p:
            fin = html.find('>', p)
            if fin < 0:
                fin = len(html)
        costo += min(CUANTIFICADOR, fin - p)
        if costo > MAX_COSTO_HTML:
            return html[:p], True
        p = html.find('<', p + 1)
    return html, False


def _cookies(valores):
    """[(nombre en minúsculas, valor, línea)] de las Set-Cookie, también si llegan juntadas con ', '."""
    salida = []
    for valor in valores:
        for linea in _SEPARA_COOKIES.split(valor):
            nombre, igual, resto = linea.split(';', 1)[0].partition('=')
            nombre = nombre.strip()
            if igual and nombre and nombre.isascii():
                salida.append((nombre.translate(borde._MINUSCULAS), resto.strip(), linea))
    return salida


def distribucion(valor):
    """El nombre de la distribución que marca el valor de una cabecera, o None."""
    if not isinstance(valor, str):
        return None
    return next((n for n, p in _DISTROS if p.search(valor)), None)


def entradas(cabeceras=None, cuerpo=None, scripts=()):
    """Lo que el motor lee de una respuesta, sin lo del borde: {'headers': {nombre: [valores]}, 'cookies': {nombre:
    [valores]}, 'meta', 'scriptSrc', 'scripts', 'html', 'html_recortado' (_recortar_html), 'del_borde': [nombres que
    se quitaron]}. `cabeceras` como en
    borde.py (dict, http.client.HTTPMessage o lista de pares) y `scripts` el texto de scripts aparte que ya tenga la
    visita."""
    pares = borde._pares(cabeceras)
    del_borde = sorted({n for ns in borde.por_cabeceras(pares).values() for n in ns})
    fuera = {n for n in del_borde if not n.startswith('set-cookie:')}
    prefijos = tuple(n.split(':', 1)[1] for n in del_borde if n.startswith('set-cookie:'))
    headers, set_cookie = {}, []
    for nombre, valor in pares:
        if nombre == 'set-cookie':
            set_cookie.append(valor)
        elif nombre not in fuera:
            headers.setdefault(nombre, []).append(valor)
    cookies = {}
    for nombre, valor, linea in _cookies(set_cookie):
        if prefijos and nombre.startswith(prefijos):
            continue
        cookies.setdefault(nombre, []).append(valor[:MAX_VALOR])
        headers.setdefault('set-cookie', []).append(linea[:MAX_VALOR])
    html = _html(cuerpo)
    lector = _Html(html)
    total = sum(map(len, lector.scripts))
    for s in borde._varios(scripts, MAX_SCRIPTS):
        if isinstance(s, str) and s.strip() and total < MAX_TEXTO_SCRIPTS:
            lector.scripts.append(s[:min(MAX_SCRIPT, MAX_TEXTO_SCRIPTS - total)])
            total += len(lector.scripts[-1])
    html, recortado = _recortar_html(html)
    return {'headers': headers, 'cookies': cookies, 'meta': lector.meta, 'scriptSrc': lector.script_src,
            'scripts': lector.scripts, 'html': html, 'html_recortado': recortado, 'del_borde': del_borde}


# ---------------------------------------------------------------- motor

def resolver_version(plantilla, regex, valor):
    """La versión de un patrón que calzó (resolveVersion de Wappalyzer): '\\1' por el grupo 1, '\\1?a:b' por a si el
    grupo calzó y b si no. Un grupo de más de 10 caracteres no se usa."""
    if not plantilla:
        return ''
    m = regex.search(valor)
    if not m:
        return ''
    resuelta = plantilla
    grupos = [m.group(0)] + list(m.groups())
    for i, g in enumerate(grupos):
        if len(g if g is not None else 'undefined') > 10:   # como String(undefined) en JavaScript
            continue
        ternario = re.search(r'\\%d\?([^:]+):(.*)$' % i, plantilla)
        if ternario:
            resuelta = plantilla.replace(ternario.group(0), ternario.group(1) if g else ternario.group(2))
        resuelta = resuelta.strip().replace('\\%d' % i, g or '')
    return re.sub(r'\\\d', '', resuelta, count=1).strip()


class _Reloj:
    def __init__(self, reloj, tope):
        self.reloj, self.fin = reloj, reloj() + tope

    def vencido(self):
        return self.reloj() > self.fin


def _buscar(tecnologias, datos, reloj, vistos):
    """Las detecciones [(nombre, campo, llave, versión, confianza, valor)] de `tecnologias` en `datos`. False si se
    acabó el tiempo."""
    for nombre in tecnologias:
        t = datos['tecnologias'][nombre]
        for campo, patrones in t['patrones'].items():
            entrada = vistos[campo]
            for llave, regex, version, confianza in patrones:
                if reloj.vencido():
                    return False
                if campo in CON_LLAVE:
                    valores = entrada.get(llave, [])
                elif campo == 'html':
                    valores = [entrada] if entrada else []
                else:
                    valores = entrada
                for valor in valores:
                    if regex.search(valor):
                        yield (nombre, campo, llave, resolver_version(version, regex, valor), confianza, valor)
    return True


def _detectar(tecnologias, datos, vistos, reloj, salida):
    """Agrega a `salida` las detecciones; True si terminó antes del tope."""
    busqueda = _buscar(tecnologias, datos, reloj, vistos)
    while True:
        try:
            salida.append(next(busqueda))
        except StopIteration as fin:
            return fin.value is not False


def _con_implicadas(nombres, todas):
    """Los nombres y los que implican, hasta que no salga ninguno nuevo."""
    salida, pendientes = set(nombres), list(nombres)
    while pendientes:
        for implicada, _, _ in todas[pendientes.pop()]['implies']:
            if implicada in todas and implicada not in salida:
                salida.add(implicada)
                pendientes.append(implicada)
    return salida


def _distribucion_de(campo, llave, valor, de_la_respuesta):
    if campo != 'headers':
        return None
    return distribucion(valor) or (de_la_respuesta if llave in CABECERAS_DEL_SERVIDOR else None)


def analizar(estado, cabeceras=None, cuerpo=None, scripts=(), datos=None, reloj=time.monotonic):
    """Las tecnologías del sitio en una respuesta de la visita web.

    {'tecnologias': [{'nombre', 'version' (o None), 'categorias', 'cpe' (o None), 'confianza', 'senales'
    ('campo:llave' de lo que calzó, nunca el valor), 'distribucion' (o None), 'implicada_por' (o None)}] o None,
    'reto': lo de borde.reto() o None, 'completo': si se revisaron todos los patrones con todo el html, 'del_borde':
    las cabeceras que se quitaron por ser del CDN o WAF}. Con reto, 'tecnologias' es None: sin cobertura, nunca 0.
    Primero las de más confianza, luego por nombre."""
    pares = borde._pares(cabeceras)
    datos = datos or cargar()
    reto = borde.reto(estado, pares, cuerpo)
    if reto:
        return {'tecnologias': None, 'reto': reto, 'completo': False, 'del_borde': []}
    vistos = entradas(pares, cuerpo, scripts)
    de_la_respuesta = next((d for c in CABECERAS_DEL_SERVIDOR for v in vistos['headers'].get(c, [])
                            for d in [distribucion(v)] if d), None)
    tiempo = _Reloj(reloj, TOPE_SEGUNDOS)
    todas = datos['tecnologias']
    detecciones = []
    sin_requisito = [n for n, t in todas.items() if not t['requires'] and not t['requiresCategory']]
    completo = _detectar(sin_requisito, datos, vistos, tiempo, detecciones)
    hechas = set()
    while completo:   # las que requieren una tecnología o una categoría que ya salió, también implicada (driver.js)
        salieron = _con_implicadas({d[0] for d in detecciones}, todas)
        cats = {c for n in salieron for c in todas[n]['cats']}
        faltan = [n for n, t in todas.items() if n not in hechas and (t['requires'] or t['requiresCategory'])
                  and all(r in salieron for r in t['requires']) and all(c in cats for c in t['requiresCategory'])]
        if not faltan:
            break
        hechas |= set(faltan)
        completo = _detectar(faltan, datos, vistos, tiempo, detecciones)
    resueltas = {}
    for nombre, campo, llave, version, confianza, valor in detecciones:
        r = resueltas.setdefault(nombre, {'nombre': nombre, 'version': '', 'confianza': 0, 'senales': [],
                                          'distribucion': None, 'implicada_por': None})
        r['confianza'] = min(100, r['confianza'] + confianza)
        senal = campo if llave is None else '%s:%s' % (campo, llave)
        if senal not in r['senales']:
            r['senales'].append(senal)
        numero = re.match(r'\d+', version)
        if len(r['version']) < len(version) <= MAX_LARGO_VERSION and (int(numero.group()) if numero else 0) < 10000:
            r['version'] = version
            r['distribucion'] = _distribucion_de(campo, llave, valor, de_la_respuesta)
    for nombre in list(resueltas):   # excludes
        for excluida in todas[nombre]['excludes'] if nombre in resueltas else ():
            resueltas.pop(excluida, None)
    cambio = True
    while cambio:   # implies
        cambio = False
        for nombre, r in list(resueltas.items()):
            for implicada, version, confianza in todas[nombre]['implies']:
                if implicada in todas and implicada not in resueltas:
                    resueltas[implicada] = {'nombre': implicada, 'version': version,
                                            'confianza': min(r['confianza'], confianza), 'senales': [],
                                            'distribucion': None, 'implicada_por': nombre}
                    cambio = True
    salida = []
    for r in resueltas.values():
        t = todas[r['nombre']]
        salida.append(dict(r, version=r['version'] or None, categorias=[CATEGORIAS[c] for c in t['cats']],
                           cpe=t['cpe'], senales=sorted(r['senales'])))
    salida.sort(key=lambda r: (-r['confianza'], r['nombre']))
    return {'tecnologias': salida, 'reto': None, 'completo': completo and not vistos['html_recortado'],
            'del_borde': vistos['del_borde']}


def main(argv):
    if len(argv) != 2:
        print('uso: python -m cirdan.recolectores.huellas <ruta de wappalyzer-6.10.54.tgz>', file=sys.stderr)
        return 2
    datos = generar(argv[1])
    ARCHIVO.write_text(serializar(datos), encoding='utf-8', newline='\n')
    f = datos['filtro']
    print('%s: %d tecnologías (%d con CPE) de %d, %d patrones descartados' % (
        ARCHIVO.name, f['tecnologias'], f['con_cpe'], datos['procedencia']['tecnologias_en_paquete'],
        len(f['patrones_descartados'])))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

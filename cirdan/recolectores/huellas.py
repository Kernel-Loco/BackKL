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
- meta (name o property y content), scriptSrc (el src de cada <script> como vino y, si la visita pasa la URL de la
  página, también resuelto contra ella, como el DOM que lee Wappalyzer: un patrón calza si calza con cualquiera de
  los dos), scripts (el texto de cada <script> del HTML, y el de los scripts que pase la visita) y html (el cuerpo).
Topes: MAX_HTML del cuerpo, MAX_VALOR por cabecera (el de borde._pares) y MAX_CABECERAS entre todas las que no son
Set-Cookie (las Set-Cookie ya llevan borde.MAX_COOKIES entre todas), MAX_SCRIPTS, MAX_SRC, MAX_ETIQUETA, MAX_SCRIPT y
MAX_TEXTO_SCRIPTS, y TOPE_SEGUNDOS para todo el análisis. re de Python no corta una regex a la mitad: el tope de
tiempo se revisa antes de cada valor que se compara con cada patrón (el src resuelto y el crudo cuentan como dos), y
si se pasa el análisis queda incompleto ('completo': False) con lo que ya salió. Por eso + y * llevan tope de 250,
como en Wappalyzer, y también {n,}, y el html se recorta donde las regex '<[^>]{1,250}' pasarían de MAX_COSTO_HTML
(_recortar_html). Todo tope que deja algo sin leer va en 'recortes', pero solo los de DEJAN_INCOMPLETO dejan
'completo' en False (las reglas, en analizar()).
Una respuesta armada para trabar las regex no pasa de TOPE_SEGUNDOS más una regex sobre un valor
(pruebas/test_huellas.py).

Reto. Si borde.reto() dice que la respuesta es un reto o un bloqueo del WAF, no se analiza: 'tecnologias' es None,
que quiere decir sin cobertura, nunca 0 tecnologías, y la visita pone el sitio en sin_revisar con borde.aviso().

Distribución. Una versión que trae la marca de una distribución en su pedazo de la cabecera, como 'nginx/1.24.0
(Ubuntu)' o 'PHP/8.1.2-1ubuntu2.14', lleva 'distribucion': la distribución le sigue mandando parches que
endoflife.date y la NVD no ven (_plan de RC-66, etica-1), así que soporte.py y nvd.py no la marcan. El pedazo es el
producto que calzó con los comentarios entre paréntesis que le siguen (_pedazo): en 'Apache/2.4.52 (Ubuntu)
PHP/8.1.27' el '(Ubuntu)' es de Apache y no de PHP. La marca de las cabeceras server y x-powered-by de la respuesta,
como 'Apache/2.4.6 (CentOS)' con 'X-Powered-By: PHP/5.4.16', solo la heredan los servidores web y los lenguajes
(HEREDAN, todas sus categorías) sin marca propia, que son lo que la distribución empaqueta: un framework como Next.js
detrás de 'nginx (Ubuntu)' no la lleva. Tampoco la heredan un producto que la distribución no empaqueta con esa
cabecera (NO_HEREDAN, como OpenResty) ni uno cuyo pedazo trae otro comentario, como 'Apache/2.4.58 (Unix)' o
'(Win64)': se compiló aparte. Una versión con la marca de un repositorio que sigue las versiones oficiales
(SIGUEN_UPSTREAM, como el PPA de PHP de deb.sury.org en 'PHP/8.1.27-1+ubuntu22.04.1+deb.sury.org+1') no lleva
distribución ni la hereda: ahí el número sí dice qué parches tiene. Esa cabecera sí dice la distribución del
servidor ('ubuntu22.04'), y las demás versiones de la respuesta la heredan como de cualquier otra cabecera: un
'Server: Apache/2.4.52' sin marca junto a ese X-Powered-By es el Apache de Ubuntu. Solo se reconoce la marca
'deb.sury.org'. Una versión del HTML (por ejemplo el generator de WordPress) no la lleva: esa no la actualiza la
distribución.
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
from urllib.parse import urljoin

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
MAX_VALOR = borde.MAX_VALOR  # de cada cabecera: borde._pares la corta ahí, así que una de ese largo no se lee
MAX_CABECERAS = 64 * 1024    # entre todas las cabeceras que no son Set-Cookie: 99 de 8 KiB tomaban más de 5 s
MAX_SCRIPTS = 200            # <script src> y <meta> que se leen del HTML
MAX_SRC = 2 * 1024           # caracteres de cada src y de cada content de <meta>
MAX_ETIQUETA = 4 * 1024      # caracteres que se buscan hasta el '>' de un <script> o <meta>
MAX_SCRIPT = 64 * 1024       # caracteres de cada script que se analizan
MAX_TEXTO_SCRIPTS = 256 * 1024   # entre todos los scripts
MAX_COSTO_HTML = 1000000     # pasos de las regex '<[^>]{1,250}...' en el html (_recortar_html)
TOPE_SEGUNDOS = 3.0          # para todo el análisis, revisado antes de cada valor de cada patrón
CUANTIFICADOR = 250          # el tope de + y * de Wappalyzer (parsePattern)
MAX_LARGO_VERSION = 15       # Wappalyzer descarta versiones más largas (resolve)
# Los recortes que dejan 'completo' en False: solo los alcanza una respuesta fuera de lo normal (analizar()).
DEJAN_INCOMPLETO = ('MAX_CABECERAS', 'MAX_COSTO_HTML', 'MAX_VALOR')

# Marca de una distribución en el valor de una cabecera: entre paréntesis o en el sufijo de la versión del paquete.
DISTRIBUCIONES = (('Ubuntu', r'ubuntu'), ('Debian', r'debian|[+~.-]deb\d'), ('CentOS', r'centos'),
                  ('Red Hat', r'red ?hat|\brhel'), ('Fedora', r'fedora|[.-]fc\d+\b'),
                  ('Amazon Linux', r'amazon ?linux|[.-]amzn\d*\b'), ('Rocky Linux', r'rocky'),
                  ('AlmaLinux', r'alma ?linux'), ('Oracle Linux', r'oracle ?linux'), ('SUSE', r'suse|\bsles'),
                  ('Raspbian', r'raspbian'), ('Alpine', r'alpine'),
                  ('Enterprise Linux', r'[.-]el\d+(?:_\d+)?\b'))
CABECERAS_DEL_SERVIDOR = ('server', 'x-powered-by')
HEREDAN = {22, 27}           # Web servers y Programming languages: las que heredan la marca de la otra cabecera
# Productos de esas categorías que la distribución no empaqueta con esa cabecera: los trae su propio proveedor.
NO_HEREDAN = ('Jetty', 'OpenResty')
# Repositorios que siguen las versiones oficiales: su marca no es de una distribución, aunque nombre una.
SIGUEN_UPSTREAM = (r'deb\.sury\.org',)

_DISTROS = [(n, re.compile(p, re.I | re.A)) for n, p in DISTRIBUCIONES]
_UPSTREAM = re.compile('|'.join(SIGUEN_UPSTREAM), re.I | re.A)
# Un producto de la cabecera ('Apache/2.4.52') con los comentarios que le siguen (' (Ubuntu)'), o un comentario suelto.
_PEDAZO = re.compile(r'[^\s()]+(?:\s*\([^()]*\))*|\([^()]*\)', re.A)
_COMENTARIO = re.compile(r'\([^()]*\)', re.A)   # '(Unix)' o '(Win64)' en el pedazo: el producto ya dice su origen
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
    etiqueta se busca a lo más MAX_ETIQUETA caracteres y el texto avanza siempre, así que es lineal. Con `url`, cada
    src se resuelve contra ella (urljoin), como el src del DOM que lee Wappalyzer: '/glpi/js/common.min.js' de
    https://www.acme-demo.mx/ es 'https://www.acme-demo.mx/glpi/js/common.min.js'. script_src_crudo trae cada src
    como vino, en el mismo orden. 'recortes' dice qué tope dejó algo sin leer (MAX_ETIQUETA, MAX_SRC, MAX_SCRIPTS,
    MAX_SCRIPT o MAX_TEXTO_SCRIPTS)."""

    def __init__(self, html, url=None):
        self.meta, self.script_src, self.script_src_crudo, self.scripts = {}, [], [], []
        self.recortes = set()
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
                self.recortes.add('MAX_ETIQUETA')
                p = m.end()
                continue
            a = _atributos(html[m.end():fin])
            p = fin + 1
            if m.group(1).lower() == 'meta':
                llave = a.get('name') or a.get('property')
                if llave and 'content' in a:
                    if metas < MAX_SCRIPTS:
                        metas += 1
                        if len(a['content']) > MAX_SRC:
                            self.recortes.add('MAX_SRC')
                        self.meta.setdefault(llave.translate(borde._MINUSCULAS), []).append(a['content'][:MAX_SRC])
                    else:
                        self.recortes.add('MAX_SCRIPTS')
                continue
            src = a.get('src', '').strip()
            if src and not src.startswith('data:text/javascript;'):
                if len(self.script_src) < MAX_SCRIPTS:
                    resuelto = _resuelto(url, src[:MAX_SRC])
                    if len(src) > MAX_SRC or len(resuelto) > MAX_SRC:
                        self.recortes.add('MAX_SRC')
                    self.script_src.append(resuelto[:MAX_SRC])
                    self.script_src_crudo.append(src[:MAX_SRC])
                else:
                    self.recortes.add('MAX_SCRIPTS')
            cierre = _FIN_SCRIPT.search(html, p)
            texto = html[p:cierre.start() if cierre else len(html)]
            if len(texto) > MAX_SCRIPT:
                self.recortes.add('MAX_SCRIPT')
                texto = texto[:MAX_SCRIPT]
            p = cierre.end() if cierre else len(html)
            if not texto.strip():
                continue
            if len(self.scripts) >= MAX_SCRIPTS:
                self.recortes.add('MAX_SCRIPTS')
            elif total >= MAX_TEXTO_SCRIPTS or len(texto) > MAX_TEXTO_SCRIPTS - total:
                self.recortes.add('MAX_TEXTO_SCRIPTS')
            if len(self.scripts) < MAX_SCRIPTS and total < MAX_TEXTO_SCRIPTS:
                self.scripts.append(texto[:MAX_TEXTO_SCRIPTS - total])
                total += len(self.scripts[-1])


def _resuelto(url, src):
    """El src resuelto contra la URL de la página, o tal cual sin URL o si urljoin no lo puede leer."""
    if not isinstance(url, str) or not url:
        return src
    try:
        return urljoin(url[:MAX_SRC], src)
    except ValueError:   # una URL o un src con '[' sin cerrar, como '//[x' (urlsplit lo lee como IPv6)
        return src


def _html(cuerpo):
    """(los primeros MAX_HTML caracteres del cuerpo, si quedó algo fuera). Bytes se leen como UTF-8 y lo ilegible se
    cambia."""
    cortado = False
    if isinstance(cuerpo, (bytes, bytearray)):
        cortado = len(cuerpo) > MAX_HTML * 4
        cuerpo = bytes(cuerpo[:MAX_HTML * 4]).decode('utf-8', errors='replace')
    if not isinstance(cuerpo, str):
        return '', False
    return cuerpo[:MAX_HTML], cortado or len(cuerpo) > MAX_HTML


def _recortar_html(html):
    """(html, recortado): el html hasta donde las regex del html de Wappalyzer con '[^>]{' (85 de las 121 de
    huellas_wappalyzer.json, 18 de ellas empiezan con '<[^>]') caben en MAX_COSTO_HTML. Cada '<' les cuesta hasta el
    siguiente '>', con tope de 250: una página real de 256 KiB cuesta unos 200 mil y una armada de puros '<', 65
    millones (31 s). Lo que queda fuera no se revisa con las regex del html, pero sí con el lector de <meta> y
    <script>."""
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
    """El nombre de la distribución que marca el valor de una cabecera, o None. Es la del sistema del servidor: la
    marca de SIGUEN_UPSTREAM (como '8.1.27-1+ubuntu22.04.1+deb.sury.org+1') no la quita, porque 'ubuntu22.04' dice
    que el servidor es Ubuntu, aunque esa versión de PHP no sea de Ubuntu (_distribucion_de)."""
    if not isinstance(valor, str):
        return None
    return next((n for n, p in _DISTROS if p.search(valor)), None)


def _pedazo(valor, inicio, fin):
    """Los productos de la cabecera (cada uno con los comentarios entre paréntesis que le siguen, _PEDAZO) que tocan
    valor[inicio:fin], juntos con un espacio: el pedazo de 'Apache/2.4.52 (Ubuntu) PHP/8.1.27' donde calzó PHP es
    'PHP/8.1.27', y el de Apache, 'Apache/2.4.52 (Ubuntu)'. Un patrón que calza vacío toca el producto que sigue."""
    fin = max(fin, inicio + 1)
    return ' '.join(m.group() for m in _PEDAZO.finditer(valor) if m.end() > inicio and m.start() < fin)


def entradas(cabeceras=None, cuerpo=None, scripts=(), url=None):
    """Lo que el motor lee de una respuesta, sin lo del borde: {'headers': {nombre: [valores]}, 'cookies': {nombre:
    [valores]}, 'meta', 'scriptSrc' (resueltos con `url`), 'scriptSrc_crudo' (los mismos src como vinieron),
    'scripts', 'html', 'recortes', 'del_borde': [nombres que se quitaron]}. `cabeceras` como en borde.py (dict,
    http.client.HTTPMessage o lista de pares), `scripts` el texto de scripts aparte que ya tenga la visita y `url` la
    de la página, para resolver los src relativos.

    'recortes' lista, ordenados, los topes que dejaron algo sin leer: MAX_HTML, MAX_CABECERAS (un valor que ya no cabe
    entero se salta, nunca se corta, porque 'nginx/1.2' de 'nginx/1.24.0' sería otra versión), MAX_VALOR (lo mismo
    con un valor que llega con MAX_VALOR caracteres o más, que borde._pares ya cortó o que llegó con ese largo justo,
    y con una Set-Cookie de más: se saltan enteros), MAX_COOKIES (las Set-Cookie llegan con borde.MAX_COOKIES entre
    todas), MAX_ETIQUETA (un
    <script> o <meta> sin '>' en MAX_ETIQUETA caracteres, que no se lee), MAX_SRC, MAX_SCRIPTS, MAX_SCRIPT,
    MAX_TEXTO_SCRIPTS y MAX_COSTO_HTML (_recortar_html). Cuáles dejan el análisis incompleto lo dice analizar().

    Un error al recorrer `cabeceras` o `scripts` (por ejemplo un generador que lanza OSError) no se atrapa y sale de
    aquí, como en borde._varios: con [] se tomaría lo que no se leyó por un negativo. La visita debe atraparlo por
    sitio y dejar ese sitio sin cobertura (en sin_revisar de borde.cobertura), no tumbar toda la fuente."""
    pares = borde._pares(cabeceras)
    del_borde = sorted({n for ns in borde.por_cabeceras(pares).values() for n in ns})
    fuera = {n for n in del_borde if not n.startswith('set-cookie:')}
    prefijos = tuple(n.split(':', 1)[1] for n in del_borde if n.startswith('set-cookie:'))
    headers, set_cookie, recortes = {}, [], set()
    resto = MAX_CABECERAS   # de toda la respuesta, como borde.MAX_COOKIES en set-cookie
    for nombre, valor in pares:
        if nombre == 'set-cookie':
            set_cookie.append(valor)
        elif nombre not in fuera:
            if len(valor) >= MAX_VALOR:   # puede venir cortado por borde._pares: tampoco se lee, ni su nombre
                recortes.add('MAX_VALOR')
                continue
            if len(valor) > resto:   # lo que no cabe entero no se lee, ni su nombre: cortarlo daría otra versión
                recortes.add('MAX_CABECERAS')
                continue
            resto -= len(valor)
            headers.setdefault(nombre, []).append(valor)
    if sum(map(len, set_cookie)) >= borde.MAX_COOKIES:
        recortes.add('MAX_COOKIES')
    cookies = {}
    for nombre, valor, linea in _cookies(set_cookie):
        if prefijos and nombre.startswith(prefijos):
            continue
        if len(linea) > MAX_VALOR:   # tampoco se lee cortada
            recortes.add('MAX_VALOR')
            continue
        cookies.setdefault(nombre, []).append(valor)
        headers.setdefault('set-cookie', []).append(linea)
    html, cortado = _html(cuerpo)
    if cortado:
        recortes.add('MAX_HTML')
    lector = _Html(html, url)
    recortes |= lector.recortes
    total = sum(map(len, lector.scripts))
    aparte = borde._varios(scripts, MAX_SCRIPTS + 1)   # uno de más para saber si quedó alguno fuera
    if len(aparte) > MAX_SCRIPTS:
        recortes.add('MAX_SCRIPTS')
    for s in aparte[:MAX_SCRIPTS]:
        if isinstance(s, str) and s.strip():
            if len(s) > MAX_SCRIPT:
                recortes.add('MAX_SCRIPT')
            texto = s[:MAX_SCRIPT]
            if len(texto) > MAX_TEXTO_SCRIPTS - total:
                recortes.add('MAX_TEXTO_SCRIPTS')
            if total < MAX_TEXTO_SCRIPTS:
                lector.scripts.append(texto[:MAX_TEXTO_SCRIPTS - total])
                total += len(lector.scripts[-1])
    html, recortado = _recortar_html(html)
    if recortado:
        recortes.add('MAX_COSTO_HTML')
    return {'headers': headers, 'cookies': cookies, 'meta': lector.meta, 'scriptSrc': lector.script_src,
            'scriptSrc_crudo': lector.script_src_crudo, 'scripts': lector.scripts, 'html': html,
            'recortes': sorted(recortes), 'del_borde': del_borde}


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
    """Las detecciones [(nombre, campo, llave, versión, confianza, valor, (inicio, fin) de lo que calzó)] de
    `tecnologias` en `datos`. False si se acabó el tiempo. El reloj se revisa antes de cada patrón y antes de cada
    valor, también entre el src resuelto y el crudo: una cabecera repetida muchas veces no pasa del tope por más de
    una regex sobre un valor. Un src se compara resuelto y, si es otro, también como vino ('scriptSrc_crudo'): calza
    con cualquiera y da una sola detección, así que su señal y su confianza no cuentan dos veces."""
    for nombre in tecnologias:
        t = datos['tecnologias'][nombre]
        for campo, patrones in t['patrones'].items():
            entrada = vistos[campo]
            crudos = (vistos.get('scriptSrc_crudo') or []) if campo == 'scriptSrc' else []
            for llave, regex, version, confianza in patrones:
                if reloj.vencido():
                    return False
                if campo in CON_LLAVE:
                    valores = entrada.get(llave, [])
                elif campo == 'html':
                    valores = [entrada] if entrada else []
                else:
                    valores = entrada
                for i, valor in enumerate(valores):
                    if i and reloj.vencido():
                        return False
                    formas = (valor, crudos[i]) if i < len(crudos) and crudos[i] != valor else (valor,)
                    for j, forma in enumerate(formas):
                        if j and reloj.vencido():   # el src crudo es otro valor
                            return False
                        m = regex.search(forma)
                        if m:
                            yield (nombre, campo, llave, resolver_version(version, regex, forma), confianza, forma,
                                   m.span())
                            break
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


def _distribucion_de(nombre, campo, llave, valor, donde, de_la_respuesta, cats):
    """La distribución de una versión que salió de valor[donde[0]:donde[1]], con la marca de su pedazo (_pedazo), no
    la de toda la cabecera: None si el pedazo trae la de SIGUEN_UPSTREAM, la de su propia marca, o la de las
    cabeceras del servidor (`de_la_respuesta`) solo para HEREDAN. No la hereda un producto de NO_HEREDAN ni uno cuyo
    pedazo trae un comentario que no es de una distribución, como 'Apache/2.4.58 (Unix)' o 'Apache/2.4.41 (Win64)':
    ese Apache se compiló aparte y no es el de la distribución que diga la otra cabecera."""
    if campo != 'headers':
        return None
    pedazo = _pedazo(valor, *donde)
    if _UPSTREAM.search(pedazo):
        return None
    propia = distribucion(pedazo)
    if propia:
        return propia
    hereda = (llave in CABECERAS_DEL_SERVIDOR and cats and set(cats) <= HEREDAN and nombre not in NO_HEREDAN
              and not _COMENTARIO.search(pedazo))
    return de_la_respuesta if hereda else None


def analizar(estado, cabeceras=None, cuerpo=None, scripts=(), datos=None, reloj=time.monotonic, url=None):
    """Las tecnologías del sitio en una respuesta de la visita web. `url` es la de la página, para resolver los src
    relativos de los <script> como el DOM (sin ella se comparan como vienen). Solo se resuelven con esa url: un
    <base href> del HTML no se lee.

    {'tecnologias': [{'nombre', 'version' (o None), 'categorias', 'cpe' (o None), 'confianza', 'senales'
    ('campo:llave' de lo que calzó, nunca el valor), 'distribucion' (o None), 'implicada_por' (o None)}] o None,
    'reto': lo de borde.reto() o None, 'completo', 'recortes': los de entradas(), para el aviso, 'del_borde': las
    cabeceras que se quitaron por ser del CDN o WAF}. Con reto, 'tecnologias' es None: sin cobertura, nunca 0.
    Primero las de más confianza, luego por nombre.

    'completo' dice que las huellas vieron lo que la visita les dio, en la medida en que una página normal se lee: es
    False con reto (no se analizó), si se acabó TOPE_SEGUNDOS antes de revisar todos los patrones o si hubo un
    recorte de DEJAN_INCOMPLETO: MAX_CABECERAS (más de 64 KiB de cabeceras sin las Set-Cookie), MAX_VALOR (una
    cabecera de MAX_VALOR caracteres o más, o una Set-Cookie de más, que se saltan enteras porque cortadas darían
    otra versión) y MAX_COSTO_HTML (el html armado que corta _recortar_html). Esos solo los alcanza una respuesta
    fuera de lo normal, y ahí lo que no se leyó puede esconder cualquier tecnología. Los demás topes (MAX_HTML,
    MAX_COOKIES, MAX_ETIQUETA, MAX_SRC, MAX_SCRIPTS, MAX_SCRIPT y MAX_TEXTO_SCRIPTS) van en 'recortes' y no lo dejan
    en False: son cuánto de una página se lee, y una página normal los alcanza (un HTML de más de 256 KiB, o cuatro
    scripts de 64 KiB de la visita más uno en línea). Si la visita deja sin cobertura el sitio con 'completo' False,
    con esos topes sus hallazgos nunca se cerrarían. El costo: una tecnología que solo se ve más allá de uno de ellos
    no sale, y su hallazgo de antes se cierra.

    Un error al recorrer `cabeceras` o `scripts` sale de aquí (entradas()): la visita debe atraparlo por sitio y
    dejar ese sitio sin cobertura (en sin_revisar de borde.cobertura), no tumbar toda la fuente."""
    pares = borde._pares(cabeceras)
    datos = datos or cargar()
    reto = borde.reto(estado, pares, cuerpo)
    if reto:
        return {'tecnologias': None, 'reto': reto, 'completo': False, 'recortes': [], 'del_borde': []}
    vistos = entradas(pares, cuerpo, scripts, url)
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
    for nombre, campo, llave, version, confianza, valor, donde in detecciones:
        r = resueltas.setdefault(nombre, {'nombre': nombre, 'version': '', 'confianza': 0, 'senales': [],
                                          'distribucion': None, 'implicada_por': None})
        r['confianza'] = min(100, r['confianza'] + confianza)
        senal = campo if llave is None else '%s:%s' % (campo, llave)
        if senal not in r['senales']:
            r['senales'].append(senal)
        numero = re.match(r'\d+', version)
        if len(r['version']) < len(version) <= MAX_LARGO_VERSION and (int(numero.group()) if numero else 0) < 10000:
            r['version'] = version
            r['distribucion'] = _distribucion_de(nombre, campo, llave, valor, donde, de_la_respuesta,
                                                 todas[nombre]['cats'])
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
    incompleto = set(vistos['recortes']) & set(DEJAN_INCOMPLETO)
    return {'tecnologias': salida, 'reto': None, 'completo': completo and not incompleto,
            'recortes': vistos['recortes'], 'del_borde': vistos['del_borde']}


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

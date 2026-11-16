"""Subdominios con subfinder en modo pasivo (#14b, RC-184).

subfinder (ProjectDiscovery, MIT) junta subdominios de fuentes pasivas públicas, sin tocar los servidores del
dominio: no resuelve DNS, no hace fuerza bruta y no prueba comodines. Este recolector lo corre como proceso aparte
y devuelve solo activos 'subdomain', con las mismas llaves que los de ct_logs donde aplican: 'fuente' ('subfinder')
y 'origen' (las fuentes de subfinder que vieron el nombre, en orden). No emite hallazgos (CODIGOS vacío) y no es
complemento de ct_logs: tiene su fila en data_sources, sus reintentos y su límite diario. La semilla 005 la sembró
apagada y la 016 la prende con una sola fuente, commoncrawl, la única de las 20 revisadas el 15 nov cuyos términos
permiten el uso automático y mostrar sus datos a terceros (decisión 6 de docs/servicios_externos.md).

Modo pasivo y nada más:
- lista blanca fija con -s (FUENTES_SUBFINDER) y las EXCLUIDAS con -es como cinturón, por si una versión nueva cambia
  la lista por omisión,
- nunca -active, -nW, -oI, -ip, -all, -r, -rL ni -recursive (resolverían DNS o sumarían fuentes que no se revisaron),
- -duc: sin la consulta de versión a api.pdtm.sh, que manda un identificador de la máquina y no es fuente pública,
- con -v y sin -silent: subfinder 2.17.0 solo escribe 'Encountered an error with source ...' en stderr con -v. Sin él
  una corrida sin red sale con 0 y sin ningún aviso, y pasaría por 0 subdominios (y al grabar pisaría la grabación),
- entorno limpio: solo PATH, HOME y XDG_CONFIG_HOME en una carpeta temporal que se borra al terminar. subfinder lee
  llaves de variables <FUENTE>_API_KEY y escribe su config.yaml al arrancar, así que no hereda nada de la API.

Riesgo aceptado: subfinder 2.17.0 no verifica TLS con sus fuentes (InsecureSkipVerify en pkg/subscraping/agent.go).
No les manda llaves ni datos de la empresa, solo el dominio, y recibe nombres. Un nombre falso solo agrega un activo
que #23 cruzará con las demás fuentes.

Si subfinder llega a su tiempo máximo (-max-time), corta la enumeración y sale con código 0 con lo que tenga. Por eso
se mide cuánto tardó y, si llegó a ese tiempo, el resultado lleva el aviso INCOMPLETO.

Modos: 'vivo' corre subfinder; 'grabar' además guarda la salida ya leída (líneas y avisos) en
cirdan/recolectores/respuestas_grabadas/subfinder/<dominio>/ con la Grabadora del contrato (#13); 'reproducir' solo
lee esa grabación y no ejecuta nada. No tiene línea de comandos propia. En la imagen, el usuario cirdan es dueño de
respuestas_grabadas/subfinder/ y de nada más (Dockerfile), así que puede grabar subfinder dentro del contenedor.

commoncrawl (pkg/subscraping/sources/commoncrawl/commoncrawl.go de v2.17.0) pide collinfo.json y luego el CDX de un
índice por cada uno de los últimos 5 años, en un orden al azar. Si un año responde 404 ('No Captures found': ese
índice no tiene capturas del dominio) deja de buscar en los años que faltan. Ese 404 no es una fuente caída: el
resultado sigue, con el aviso SIN_CAPTURAS. Cualquier otro error sí lo es. Al grabar, 0 nombres con SIN_CAPTURAS no
se guarda (FuenteNoResponde): como el orden es al azar, el primer año pudo no tener capturas aunque otros sí, y esa
corrida vacía pisaría una grabación buena.

Consultas del límite diario (#13b): peticiones HTTP, como en las demás fuentes. Cada corrida en vivo o al grabar
cuenta MAX_CONSULTAS (las 6 de commoncrawl, el máximo, porque subfinder no dice cuántas hizo), y 0 al reproducir.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import NOMBRE_VALIDO, Activo, FuenteNoResponde, Grabadora, Resultado, en_alcance_nombre

FUENTE = 'subfinder'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'subfinder'

# Solo activos: ningún código de regla (pruebas/test_catalogo_reglas.py acepta el dict vacío).
CODIGOS = {}

# Fuentes pasivas sin llave que se usan: solo las que pasan la regla de la decisión 6 de docs/servicios_externos.md
# (sus términos publicados permiten el uso automático y mostrar sus datos a terceros). commoncrawl no va por omisión
# en subfinder (IsDefault false): solo corre porque se pide por nombre con -s.
FUENTES_SUBFINDER = ('commoncrawl',)

# Se excluyen siempre, aunque una versión nueva las ponga por omisión (subfinder acepta en -es nombres que no conoce):
# - crtsh y certspotter: duplican a #14 (ct_logs) y se saltarían su límite diario. crtsh además abre PostgreSQL sin TLS.
#   shodanct y merklemap también son Certificate Transparency.
# - censys: sus términos no permiten dar sus datos a terceros.
# - hudsonrock, intelx y leakix: datos de equipos infectados, filtraciones y fugas. Van contra las reglas 2 y 8.
# - Revisadas el 15 nov sin pasar la regla: anubis, crtname, digitorus, hackertarget, rapiddns, subdomaincenter, submd
#   y thc (las 8 de antes), alienvault, driftnet y urlscan (sus términos lo prohíben), waybackarchive (solo para
#   investigación), sitedossier (sin términos) y reconcloud, riddler, threatcrowd y threatminer (sitio caído).
EXCLUIDAS = ('crtsh', 'certspotter', 'censys', 'hudsonrock', 'intelx', 'leakix',
             'anubis', 'crtname', 'digitorus', 'hackertarget', 'rapiddns', 'subdomaincenter', 'submd', 'thc',
             'alienvault', 'driftnet', 'urlscan', 'waybackarchive', 'sitedossier', 'shodanct', 'merklemap',
             'reconcloud', 'riddler', 'threatcrowd', 'threatminer')

ANIOS_COMMONCRAWL = 5        # maxYearsBack de commoncrawl.go: un CDX por año
MAX_CONSULTAS = 1 + ANIOS_COMMONCRAWL    # collinfo.json más un CDX por año: peticiones HTTP de una corrida (#13b)
TIMEOUT_FUENTE = 30          # segundos por petición HTTP de cada fuente (-timeout)
MAX_MINUTOS = 5              # minutos de toda la enumeración (-max-time)
TIMEOUT = 360                # segundos del proceso completo: los 5 minutos más margen para arrancar y escribir
CONSULTA = 'subfinder:'      # consulta de la grabadora: subfinder_<dominio>.json
INCOMPLETO = 'subfinder: la lista puede estar incompleta (llegó a su tiempo máximo)'  # cortó por -max-time
SIN_CAPTURAS = ('subfinder: commoncrawl no tiene capturas del dominio en uno de los años que revisó y no buscó en los '
                'que faltaban (la lista puede estar incompleta)')

FALLA_FUENTE = re.compile(r'Encountered an error with source ([A-Za-z0-9_-]{1,40}): ([^\n]*)')
# El 404 del CDX de commoncrawl: el índice de ese año no tiene capturas del dominio.
CDX_SIN_CAPTURAS = re.compile(r'unexpected status code 404 received from https://index\.commoncrawl\.org/'
                              r'CC-MAIN-[0-9]{4}-[0-9]{2}-index\?')
NOMBRE_FUENTE = re.compile(r'[a-z0-9_-]{1,40}')


def _binario():
    """Ruta de subfinder en el PATH, o None si no está instalado."""
    return shutil.which('subfinder')


def _ejecutar(comando, **opciones):
    return subprocess.run(comando, **opciones)


def comando(binario, dominio):
    """La línea de subfinder para un dominio. Siempre pasiva: lista blanca, excluidas, JSON con todas las fuentes de
    cada nombre (-cs), sin color, sin consulta de versión y con -v para que escriba el error de cada fuente."""
    return [binario, '-d', dominio, '-s', ','.join(FUENTES_SUBFINDER), '-es', ','.join(EXCLUIDAS), '-oJ', '-cs', '-nc',
            '-duc', '-v', '-timeout', str(TIMEOUT_FUENTE), '-max-time', str(MAX_MINUTOS)]


def _cuantos(n, singular, plural):
    return '%d %s' % (n, singular if n == 1 else plural)


def _texto(valor):
    """Un texto que se puede grabar en UTF-8 (un surrogate suelto de la salida queda como '?')."""
    return valor.encode('utf-8', 'replace').decode('utf-8')


def _fuentes(linea):
    """Las fuentes de una línea: 'sources' con -cs o 'source' sin él. Solo nombres con forma de fuente."""
    fuentes = linea.get('sources')
    if not isinstance(fuentes, list):
        fuentes = [linea.get('source')]
    return [f for f in fuentes if isinstance(f, str) and NOMBRE_FUENTE.fullmatch(f)]


def leer_salida(stdout, stderr):
    """{'lineas': [{host, input, sources}], 'avisos': [...], 'caidas': [...]} de una corrida de subfinder.

    Cada línea de stdout es un JSON con host, input y sources. Las que no son JSON se saltan con un aviso que dice
    cuántas. De stderr solo se toma el nombre de cada fuente que no respondió, sin URLs ni el texto del error. El 404
    del CDX de commoncrawl no la cuenta como caída: deja el aviso SIN_CAPTURAS. Con -v, stderr también trae el cuerpo
    de cada respuesta fallida, que no se lee."""
    lineas, raras = [], 0
    for texto in (stdout or '').splitlines():
        texto = texto.strip()
        if not texto:
            continue
        try:
            linea = json.loads(texto)
        except ValueError:
            raras += 1
            continue
        if not isinstance(linea, dict) or not isinstance(linea.get('host'), str):
            raras += 1
            continue
        entrada = linea.get('input')
        lineas.append({'host': _texto(linea['host']), 'input': _texto(entrada) if isinstance(entrada, str) else '',
                       'sources': _fuentes(linea)})
    caidas, sin_capturas = [], False
    for nombre, error in FALLA_FUENTE.findall(stderr or ''):
        nombre = nombre.lower()
        if nombre == 'commoncrawl' and CDX_SIN_CAPTURAS.match(error):
            sin_capturas = True
        elif nombre not in caidas:
            caidas.append(nombre)
    avisos = ['subfinder: la fuente %s no respondió' % n for n in caidas]
    if sin_capturas and 'commoncrawl' not in caidas:
        avisos.append(SIN_CAPTURAS)
    if raras:
        avisos.append('subfinder: se %s %s que no %s JSON' % (
            'saltó' if raras == 1 else 'saltaron', _cuantos(raras, 'línea', 'líneas'), 'es' if raras == 1 else 'son'))
    return {'lineas': lineas, 'avisos': avisos, 'caidas': caidas}


class ClienteSubfinder:
    """Corre subfinder y, según el modo, graba o reproduce su salida ya leída con la Grabadora del contrato (#13).

    `ejecutar(comando, **opciones)`, `binario` y `cronometro` se inyectan en las pruebas. Por omisión son
    subprocess.run, el primer subfinder del PATH y time.monotonic. `reloj` es el de la Grabadora (fecha de grabación).
    `consultas` suma MAX_CONSULTAS cada vez que el proceso arranca."""

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, ejecutar=None, binario=None, nueva=False, reloj=None,
                 timeout=TIMEOUT, cronometro=None):
        self.modo, self.timeout = modo, timeout
        self.grabadora = Grabadora(carpeta, modo, nueva=nueva, reloj=reloj)
        self.ejecutar = ejecutar or _ejecutar
        self.binario = binario
        self.cronometro = cronometro or time.monotonic
        self.consultas = 0

    @property
    def leidas(self):
        """(archivo, fecha de grabación) de cada respuesta tomada del disco."""
        return self.grabadora.leidas

    def _correr(self, dominio):
        binario = self.binario or _binario()
        if not binario:
            raise FuenteNoResponde('subfinder no está instalado')
        with tempfile.TemporaryDirectory(prefix='cirdan-subfinder-') as casa:
            config = os.path.join(casa, 'config')
            os.makedirs(config)
            entorno = {'PATH': os.environ.get('PATH', os.defpath), 'HOME': casa, 'XDG_CONFIG_HOME': config}
            self.consultas += MAX_CONSULTAS
            inicio = self.cronometro()
            try:
                hecho = self.ejecutar(comando(binario, dominio), capture_output=True, text=True, encoding='utf-8',
                                      errors='replace', timeout=self.timeout, check=False, env=entorno, cwd=casa,
                                      stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                raise FuenteNoResponde('subfinder no terminó en %d s' % self.timeout) from None
            except OSError as e:
                raise FuenteNoResponde('no se pudo correr subfinder (%s)' % type(e).__name__) from None
            tardo = self.cronometro() - inicio
        if hecho.returncode != 0:
            raise FuenteNoResponde('subfinder terminó con código %s' % hecho.returncode)
        datos = leer_salida(hecho.stdout, hecho.stderr)
        if set(FUENTES_SUBFINDER) <= set(datos['caidas']):
            raise FuenteNoResponde('subfinder: ninguna de sus fuentes respondió (%s)' % ', '.join(FUENTES_SUBFINDER))
        avisos = datos['avisos']
        if tardo >= MAX_MINUTOS * 60:  # -max-time cortó la enumeración y salió con 0: pueden faltar nombres
            avisos.append(INCOMPLETO)
        return {'lineas': datos['lineas'], 'avisos': avisos}

    def enumerar(self, dominio):
        """{'lineas', 'avisos'} de subfinder para el dominio. Sale del disco al reproducir y se graba al grabar. Si
        subfinder no responde no se graba nada, así la grabación anterior queda intacta. Tampoco se graba una corrida
        con 0 nombres y SIN_CAPTURAS: commoncrawl pudo cortar en un año sin capturas antes de llegar a los que sí."""
        consulta = CONSULTA + dominio
        del_disco, datos = self.grabadora.de_disco(consulta)
        if del_disco:
            if not (isinstance(datos, dict) and isinstance(datos.get('lineas'), list) and
                    isinstance(datos.get('avisos'), list)):
                raise FuenteNoResponde('la grabación de subfinder de %s no se puede leer' % dominio)
            return datos
        datos = self._correr(dominio)
        if self.modo == 'grabar' and not datos['lineas'] and SIN_CAPTURAS in datos['avisos']:
            raise FuenteNoResponde('subfinder: commoncrawl no dio nombres de %s y cortó en un año sin capturas, '
                                   'así que no se graba para no pisar la grabación anterior' % dominio)
        self.grabadora.guardar(consulta, datos)
        return datos


def _normalizar(nombre):
    nombre = nombre.strip().lower().rstrip('.')
    while nombre.startswith('*.'):
        nombre = nombre[2:]
    return nombre


def subdominios(dominio, lineas):
    """(activos, fuera, invalidos): un Activo 'subdomain' por nombre, sin repetir y con las fuentes juntas.

    Cada nombre va en minúsculas, sin punto final y sin '*.' delante. El propio dominio no sale como subdominio.
    `fuera` y `invalidos` cuentan los nombres que se descartaron por no ser del dominio o por no pasar la validación
    de nombres del contrato."""
    origen, fuera, invalidos = {}, set(), set()
    for linea in lineas:
        if not isinstance(linea, dict) or not isinstance(linea.get('host'), str):
            continue
        nombre = _normalizar(linea['host'])
        if nombre == dominio:
            continue
        if not NOMBRE_VALIDO.fullmatch(nombre):
            invalidos.add(nombre)
            continue
        if not en_alcance_nombre(nombre, dominio):
            fuera.add(nombre)
            continue
        fuentes = linea.get('sources') if isinstance(linea.get('sources'), list) else []
        origen.setdefault(nombre, set()).update(f for f in fuentes if isinstance(f, str) and NOMBRE_FUENTE.fullmatch(f))
    activos = [Activo('subdomain', n, {'fuente': FUENTE, 'origen': sorted(origen[n])}) for n in sorted(origen)]
    return activos, len(fuera), len(invalidos)


def carpeta_de(dominio):
    """Carpeta de la grabación de un dominio."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' corre subfinder, 'reproducir' usa la grabación del dominio y 'grabar'
    empieza una grabación nueva."""
    return ClienteSubfinder(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'))


def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Subdominios de `dominio` según las fuentes pasivas de subfinder. `ahora` y `propios` no se usan: subfinder no
    da fechas ni busca dominios parecidos."""
    dominio = dominio.strip().lower().rstrip('.')
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.fullmatch(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res
    cliente = cliente or crear_cliente('vivo', dominio)
    datos = cliente.enumerar(dominio)
    res.consultas = cliente.consultas
    res.avisos += [a for a in datos['avisos'] if isinstance(a, str)]
    res.activos, fuera, invalidos = subdominios(dominio, datos['lineas'])
    if fuera:  # cuántos, no cuáles: pueden ser de terceros
        res.avisos.append('subfinder: %s fuera del dominio' % _descartados(fuera))
    if invalidos:
        res.avisos.append('subfinder: %s que no %s' % (_descartados(invalidos), 'es un nombre de dominio válido'
                                                         if invalidos == 1 else 'son nombres de dominio válidos'))
    return res


def _descartados(n):
    return 'se descartó 1 nombre' if n == 1 else 'se descartaron %d nombres' % n

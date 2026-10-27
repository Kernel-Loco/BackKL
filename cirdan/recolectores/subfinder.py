"""Subdominios con subfinder en modo pasivo (#14b, RC-184).

subfinder (ProjectDiscovery, MIT) junta subdominios de fuentes pasivas públicas, sin tocar los servidores del
dominio: no resuelve DNS, no hace fuerza bruta y no prueba comodines. Este recolector lo corre como proceso aparte
y devuelve solo activos 'subdomain', con las mismas llaves que los de ct_logs donde aplican: 'fuente' ('subfinder')
y 'origen' (las fuentes de subfinder que vieron el nombre, en orden). No emite hallazgos (CODIGOS vacío) y no es
complemento de ct_logs: tiene su fila en data_sources, sus reintentos y su límite diario. La semilla 005 la deja
apagada (enabled = false) hasta que #8 (RC-40) revise los términos de las 8 fuentes, haya una grabación de
olmardo.com y el contenedor pueda escribir respuestas_grabadas/.

Modo pasivo y nada más:
- lista blanca fija con -s (FUENTES_SUBFINDER) y las EXCLUIDAS con -es como cinturón, por si una versión nueva cambia
  la lista por omisión,
- nunca -active, -nW, -oI, -ip, -all, -r, -rL ni -recursive (resolverían DNS o sumarían fuentes que no se revisaron),
- -duc: sin la consulta de versión a api.pdtm.sh, que manda un identificador de la máquina y no es fuente pública,
- sin -silent: así los avisos de fuentes caídas salen en stderr y una corrida sin red no pasa por 0 subdominios,
- entorno limpio: solo PATH, HOME y XDG_CONFIG_HOME en una carpeta temporal que se borra al terminar. subfinder lee
  llaves de variables <FUENTE>_API_KEY y escribe su config.yaml al arrancar, así que no hereda nada de la API.

Riesgo aceptado: subfinder 2.17.0 no verifica TLS con sus fuentes (InsecureSkipVerify en pkg/subscraping/agent.go).
No les manda llaves ni datos de la empresa, solo el dominio, y recibe nombres. Un nombre falso solo agrega un activo
que #23 cruzará con las demás fuentes.

Si subfinder llega a su tiempo máximo (-max-time), corta la enumeración y sale con código 0 con lo que tenga. Por eso
se mide cuánto tardó y, si llegó a ese tiempo, el resultado lleva el aviso INCOMPLETO.

Modos: 'vivo' corre subfinder; 'grabar' además guarda la salida ya leída (líneas y avisos) en
cirdan/recolectores/respuestas_grabadas/subfinder/<dominio>/ con la Grabadora del contrato (#13); 'reproducir' solo
lee esa grabación y no ejecuta nada. No tiene línea de comandos propia. Hoy no se puede grabar dentro del contenedor:
el Dockerfile copia cirdan/ como root y el usuario cirdan no escribe en respuestas_grabadas/ (pausado, fuera de
RC-184).

Consultas del límite diario (#13b): una 'consulta' de subfinder es una fuente consultada en una corrida, no una
petición HTTP. rapiddns y thc paginan y subfinder no dice cuántas peticiones hizo sin -stats, que no se lee. Cada
corrida en vivo o al grabar cuenta len(FUENTES_SUBFINDER), y 0 al reproducir.
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

# Fuentes pasivas sin llave que se usan. Todas leen índices públicos y ninguna resuelve DNS.
FUENTES_SUBFINDER = ('anubis', 'crtname', 'digitorus', 'hackertarget', 'rapiddns', 'subdomaincenter', 'submd', 'thc')

# Se excluyen siempre, aunque una versión nueva las ponga por omisión:
# - crtsh y certspotter: duplican a #14 (ct_logs) y se saltarían su límite diario. crtsh además abre PostgreSQL sin TLS.
# - censys: sus términos no permiten dar sus datos a terceros.
# - hudsonrock, intelx y leakix: datos de equipos infectados, filtraciones y fugas. Van contra las reglas 2 y 8.
EXCLUIDAS = ('crtsh', 'certspotter', 'censys', 'hudsonrock', 'intelx', 'leakix')

MAX_CONSULTAS = len(FUENTES_SUBFINDER)   # una consulta por fuente consultada en cada corrida (límite diario, #13b)
TIMEOUT_FUENTE = 30          # segundos por petición HTTP de cada fuente (-timeout)
MAX_MINUTOS = 5              # minutos de toda la enumeración (-max-time)
TIMEOUT = 360                # segundos del proceso completo: los 5 minutos más margen para arrancar y escribir
CONSULTA = 'subfinder:'      # consulta de la grabadora: subfinder_<dominio>.json
INCOMPLETO = 'subfinder: la lista puede estar incompleta (llegó a su tiempo máximo)'  # cortó por -max-time

FALLA_FUENTE = re.compile(r'Encountered an error with source ([A-Za-z0-9_-]{1,40})')
NOMBRE_FUENTE = re.compile(r'[a-z0-9_-]{1,40}')


def _binario():
    """Ruta de subfinder en el PATH, o None si no está instalado."""
    return shutil.which('subfinder')


def _ejecutar(comando, **opciones):
    return subprocess.run(comando, **opciones)


def comando(binario, dominio):
    """La línea de subfinder para un dominio. Siempre pasiva: lista blanca, excluidas, JSON con todas las fuentes de
    cada nombre (-cs), sin color y sin consulta de versión."""
    return [binario, '-d', dominio, '-s', ','.join(FUENTES_SUBFINDER), '-es', ','.join(EXCLUIDAS), '-oJ', '-cs', '-nc',
            '-duc', '-timeout', str(TIMEOUT_FUENTE), '-max-time', str(MAX_MINUTOS)]


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
    cuántas. De stderr solo se toma el nombre de cada fuente que no respondió, sin URLs ni el texto del error."""
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
    caidas = []
    for nombre in FALLA_FUENTE.findall(stderr or ''):
        nombre = nombre.lower()
        if nombre not in caidas:
            caidas.append(nombre)
    avisos = ['subfinder: la fuente %s no respondió' % n for n in caidas]
    if raras:
        avisos.append('subfinder: se %s %s que no %s JSON' % (
            'saltó' if raras == 1 else 'saltaron', _cuantos(raras, 'línea', 'líneas'), 'es' if raras == 1 else 'son'))
    return {'lineas': lineas, 'avisos': avisos, 'caidas': caidas}


class ClienteSubfinder:
    """Corre subfinder y, según el modo, graba o reproduce su salida ya leída con la Grabadora del contrato (#13).

    `ejecutar(comando, **opciones)`, `binario` y `cronometro` se inyectan en las pruebas. Por omisión son
    subprocess.run, el primer subfinder del PATH y time.monotonic. `reloj` es el de la Grabadora (fecha de grabación).
    `consultas` suma una por fuente de la lista blanca cada vez que el proceso arranca."""

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
            self.consultas += len(FUENTES_SUBFINDER)
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
            raise FuenteNoResponde('subfinder: ninguna de sus %d fuentes respondió' % len(FUENTES_SUBFINDER))
        avisos = datos['avisos']
        if tardo >= MAX_MINUTOS * 60:  # -max-time cortó la enumeración y salió con 0: pueden faltar nombres
            avisos.append(INCOMPLETO)
        return {'lineas': datos['lineas'], 'avisos': avisos}

    def enumerar(self, dominio):
        """{'lineas', 'avisos'} de subfinder para el dominio. Sale del disco al reproducir y se graba al grabar. Si
        subfinder no responde no se graba nada, así la grabación anterior queda intacta."""
        consulta = CONSULTA + dominio
        del_disco, datos = self.grabadora.de_disco(consulta)
        if del_disco:
            if not (isinstance(datos, dict) and isinstance(datos.get('lineas'), list) and
                    isinstance(datos.get('avisos'), list)):
                raise FuenteNoResponde('la grabación de subfinder de %s no se puede leer' % dominio)
            return datos
        datos = self._correr(dominio)
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

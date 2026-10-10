"""Contrato de plugin de los recolectores OSINT (#13).

Cada recolector es un módulo de recolectores/ con:
- FUENTE: el código de su fila en data_sources (por ejemplo 'ct_logs').
- crear_cliente(modo, dominio): su cliente para 'vivo', 'grabar' o 'reproducir'.
- recolectar(dominio, cliente=None, ahora=None, propios=()): devuelve un Resultado.

El orquestador (#22) no llama a recolectar() directo: llama a ejecutar(), que atrapa cualquier
excepción, revisa que el resultado cumpla este esquema y aplica el filtro de alcance. Si el
recolector falla o rompe el contrato, la fuente queda en 'failed' y el escaneo sigue con las demás.
La limpieza de datos y el límite diario por fuente son de #13b. El documento completo está en
docs/contrato_plugin.md.
"""
import http.client
import ipaddress
import json
import re
import time
import urllib.error
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

CARPETA_GRABADAS = Path(__file__).resolve().parent.parent / 'respuestas_grabadas'
MODOS = ('vivo', 'grabar', 'reproducir')
ESTADOS = ('succeeded', 'failed')                                                    # scan_source_runs.status final de una corrida
TIPOS_ACTIVO = ('domain', 'subdomain', 'ip', 'service', 'certificate', 'email')      # assets.asset_type
SEVERIDADES = ('critical', 'high', 'medium', 'low')                                  # scoring_rules.base_severity
CARACTERISTICAS = ('tipo', 'antiguedad_dias', 'exposicion', 'sensibilidad')          # las del reto (lámina 7)
EXPOSICIONES = ('directa', 'publica')     # directa: el activo responde en internet. publica: el dato es público
SENSIBILIDADES = ('baja', 'media', 'alta')
MAX_INTENTO = 3                           # scan_source_runs.attempt va de 0 a 3
ESPERAS_REINTENTO = (timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=25))
SIN_GRABACION = 'no hay respuesta grabada para '
MARCA = '.grabacion'                      # inicio de la grabación en curso, dentro de la carpeta del dominio
NOMBRE_VALIDO = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
CODIGO_VALIDO = re.compile(r'^[a-z][a-z0-9_]{1,62}$')
HUELLA_VALIDA = re.compile(r'^[0-9a-f]{64}$')


class FuenteNoResponde(Exception):
    """La fuente no respondió con datos válidos después de todos los intentos."""


class SinGrabacion(FuenteNoResponde):
    """En modo reproducir no hay respuesta grabada para la consulta. No es una caída de la fuente: el recolector
    puede tomarla como aviso, pero si llega a ejecutar() la corrida queda en 'failed'."""


# ---------------------------------------------------------------- esquema

@dataclass
class Activo:
    tipo: str                      # uno de TIPOS_ACTIVO
    valor: str                     # nombre, IP, ip:puerto/protocolo, correo o huella del certificado
    atributos: dict = field(default_factory=dict)   # va a assets.attributes. ip, service y certificate llevan 'host' o 'hosts'


@dataclass
class Hallazgo:
    codigo: str                    # código de la regla (scoring_rules.code), debe existir en el catálogo (#30)
    severidad: str                 # severidad base de su regla, una de SEVERIDADES
    activo: str                    # valor del activo al que pertenece (el dominio o uno de los activos)
    titulo: str                    # en español, también va en evidencia['title']
    evidencia: dict                # va a findings.evidence, sin secretos ni contraseñas
    caracteristicas: dict          # tipo, antiguedad_dias, exposicion y sensibilidad (las del reto, para el ML)
    huella: str                    # sha256 estable para no duplicar el hallazgo entre escaneos
    clave: str = ''                # distingue hallazgos del mismo código en el mismo activo (dominio parecido, CVE, brecha)


@dataclass
class Resultado:
    dominio: str
    fuente: str = ''
    estado: str = 'succeeded'      # 'succeeded' o 'failed'
    consultas: int = 0             # peticiones hechas a la fuente, contando reintentos
    error: str = ''
    avisos: list = field(default_factory=list)
    activos: list = field(default_factory=list)
    hallazgos: list = field(default_factory=list)

    def a_dict(self):
        return asdict(self)


def _nombre_ok(nombre):
    return isinstance(nombre, str) and bool(NOMBRE_VALIDO.fullmatch(nombre.lower().rstrip('.')))


def _textos(x):
    """Todos los textos de x, incluidas las llaves de los objetos."""
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for k, v in x.items():
            yield from _textos(k)
            yield from _textos(v)
    elif isinstance(x, (list, tuple)):
        for v in x:
            yield from _textos(v)


def _cabe_en_la_base(texto):
    """Postgres no acepta el carácter nulo en text ni en jsonb, ni un surrogate suelto en UTF-8."""
    try:
        texto.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return '\x00' not in texto


def _errores_activo(a):
    """Incumplimientos de un activo según su tipo."""
    if not isinstance(a.valor, str) or not a.valor:
        return ['activo sin valor']
    if not isinstance(a.atributos, dict):
        return ['atributos de %r no es un objeto' % a.valor]
    if a.tipo not in TIPOS_ACTIVO:
        return ['activo %r con tipo inválido: %r' % (a.valor, a.tipo)]
    if a.tipo in ('domain', 'subdomain'):
        return [] if _nombre_ok(a.valor) else ['activo %r: no es un nombre de dominio válido' % a.valor]
    if a.tipo == 'email':
        usuario, _, nombre = a.valor.rpartition('@')
        return [] if usuario and '@' not in usuario and _nombre_ok(nombre) else ['activo %r: no es un correo válido' % a.valor]
    errores = []
    if a.tipo == 'ip':
        try:
            ipaddress.ip_address(a.valor)
        except ValueError:
            errores.append('activo %r: no es una IP válida' % a.valor)
    hosts = a.atributos.get('hosts') or ([a.atributos['host']] if a.atributos.get('host') else [])
    if not isinstance(hosts, list) or not hosts or not all(_nombre_ok(h) for h in hosts):
        errores.append("activo %r: necesita 'host' o 'hosts' con nombres válidos para el filtro de alcance" % a.valor)
    return errores


def validar(res, codigos=None):
    """Lista de incumplimientos del contrato (vacía si cumple). `codigos`: los del catálogo (#30), si se tienen."""
    errores = []
    if not isinstance(res.dominio, str) or not NOMBRE_VALIDO.fullmatch(res.dominio):
        errores.append('dominio inválido: %r' % (res.dominio,))
    if not isinstance(res.fuente, str) or not res.fuente:
        errores.append('falta la fuente')
    if res.estado not in ESTADOS:
        errores.append('estado inválido: %r' % (res.estado,))
    if type(res.consultas) is not int or not 0 <= res.consultas < 2 ** 63:
        errores.append('consultas debe ser un entero de 0 o más')
    if not isinstance(res.error, str):
        errores.append('error debe ser texto')
    if not isinstance(res.avisos, list) or not all(isinstance(a, str) for a in res.avisos):
        errores.append('avisos debe ser una lista de textos')
    if not isinstance(res.activos, list) or not isinstance(res.hallazgos, list):
        return errores + ['activos y hallazgos deben ser listas']
    if res.estado == 'failed' and (res.activos or res.hallazgos):
        errores.append("un resultado 'failed' no trae activos ni hallazgos")
    vistos = set()
    for a in res.activos:
        if not isinstance(a, Activo):
            errores.append('un activo no es Activo sino %s' % type(a).__name__)
            continue
        propios = _errores_activo(a)
        if propios:
            errores += propios
            continue
        if (a.tipo, a.valor) in vistos:
            errores.append('activo repetido: %s %s' % (a.tipo, a.valor))
        vistos.add((a.tipo, a.valor))
    valores = {valor for _, valor in vistos}
    if isinstance(res.dominio, str):
        valores.add(res.dominio)
    huellas, llaves = set(), set()
    for h in res.hallazgos:
        if not isinstance(h, Hallazgo):
            errores.append('un hallazgo no es Hallazgo sino %s' % type(h).__name__)
            continue
        donde = 'hallazgo %r' % (h.codigo,)
        if not isinstance(h.codigo, str) or not CODIGO_VALIDO.fullmatch(h.codigo):
            errores.append('%s: código inválido' % donde)
        elif codigos is not None and h.codigo not in codigos:
            errores.append('%s: el código no está en el catálogo de reglas' % donde)
        if h.severidad not in SEVERIDADES:
            errores.append('%s: severidad inválida %r' % (donde, h.severidad))
        if not isinstance(h.activo, str) or h.activo not in valores:
            errores.append('%s: su activo %r no es el dominio ni uno de los activos' % (donde, h.activo))
        if not isinstance(h.titulo, str) or not h.titulo:
            errores.append('%s: sin título' % donde)
        if not isinstance(h.evidencia, dict) or h.evidencia.get('title') != h.titulo:
            errores.append("%s: evidencia['title'] debe ser el título" % donde)
        c = h.caracteristicas if isinstance(h.caracteristicas, dict) else {}
        if set(c) != set(CARACTERISTICAS):
            errores.append('%s: las características deben ser %s' % (donde, ', '.join(CARACTERISTICAS)))
        else:
            if not isinstance(c['tipo'], str) or not CODIGO_VALIDO.fullmatch(c['tipo']):
                errores.append('%s: tipo inválido %r' % (donde, c['tipo']))
            if not isinstance(c['antiguedad_dias'], int) or isinstance(c['antiguedad_dias'], bool) or c['antiguedad_dias'] < 0:
                errores.append('%s: antiguedad_dias debe ser un entero de 0 o más' % donde)
            if c['exposicion'] not in EXPOSICIONES:
                errores.append('%s: exposicion inválida %r' % (donde, c['exposicion']))
            if c['sensibilidad'] not in SENSIBILIDADES:
                errores.append('%s: sensibilidad inválida %r' % (donde, c['sensibilidad']))
        if not isinstance(h.huella, str) or not HUELLA_VALIDA.fullmatch(h.huella):
            errores.append('%s: huella inválida' % donde)
        elif h.huella in huellas:
            errores.append('%s: huella repetida' % donde)
        else:
            huellas.add(h.huella)
        if not isinstance(h.clave, str):
            errores.append('%s: la clave debe ser texto' % donde)
        elif isinstance(h.codigo, str) and isinstance(h.activo, str):
            if (h.codigo, h.activo, h.clave) in llaves:
                errores.append('%s: se repite con el mismo activo y la misma clave' % donde)
            llaves.add((h.codigo, h.activo, h.clave))
    try:
        datos = res.a_dict()
        json.dumps(datos, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as e:
        errores.append('no se puede guardar como JSON: %s' % e)
    else:
        malos = [t for t in _textos(datos) if not _cabe_en_la_base(t)]
        if malos:
            errores.append('texto que la base no acepta (carácter nulo o surrogate suelto): %r' % malos[0][:60])
    return errores


# ---------------------------------------------------------------- alcance

def en_alcance_nombre(nombre, dominio):
    """El dominio autorizado o un subdominio suyo."""
    nombre, dominio = nombre.lower().rstrip('.'), dominio.lower().rstrip('.')
    return nombre == dominio or nombre.endswith('.' + dominio)


def en_alcance(activo, dominio):
    """Nombres por su nombre, correos por su dominio, y IP, servicios y certificados por su 'host' o 'hosts'."""
    if activo.tipo in ('domain', 'subdomain'):
        return en_alcance_nombre(activo.valor, dominio)
    if activo.tipo == 'email':
        return '@' in activo.valor and en_alcance_nombre(activo.valor.rsplit('@', 1)[1], dominio)
    hosts = activo.atributos.get('hosts') or [activo.atributos.get('host', '')]
    return any(en_alcance_nombre(h, dominio) for h in hosts if h)


def filtrar_alcance(res):
    """Quita los activos fuera del alcance y los hallazgos que les pertenecen, y lo deja en avisos."""
    fuera = [a for a in res.activos if not en_alcance(a, res.dominio)]
    if not fuera:
        return res
    res.activos = [a for a in res.activos if en_alcance(a, res.dominio)]
    quedan = {res.dominio} | {a.valor for a in res.activos}  # un activo de otro tipo puede tener el mismo valor
    res.hallazgos = [h for h in res.hallazgos if h.activo in quedan]
    res.avisos += ['fuera de alcance, se descartó: %s %s' % (a.tipo, a.valor) for a in fuera]
    return res


# ---------------------------------------------------------------- ejecución y reintentos

def _texto_error(e):
    try:
        return '%s: %s' % (type(e).__name__, e)
    except Exception:  # una excepción cuyo texto también falla
        return type(e).__name__


def _conteo(n):
    return n if type(n) is int and 0 <= n < 2 ** 63 else 0


def ejecutar(recolector, dominio, modo='vivo', ahora=None, propios=(), codigos=None):
    """Lo que llama el orquestador: nunca lanza excepciones y siempre devuelve un Resultado del contrato.

    Si el dominio no es un nombre válido, no llama al recolector. El resultado tiene que ser del dominio
    autorizado y de la fuente del recolector. Primero se valida y luego se filtra por alcance, así un activo
    mal formado deja la fuente en 'failed' en lugar de perderse.
    """
    fuente = getattr(recolector, 'FUENTE', '') or getattr(recolector, '__name__', '?')
    fuente = fuente if isinstance(fuente, str) else '?'
    autorizado = dominio.strip().lower().rstrip('.') if isinstance(dominio, str) else ''
    cliente = None

    def fallido(error, consultas=0):
        return Resultado(autorizado, fuente, estado='failed', consultas=_conteo(consultas), error=error)

    if not NOMBRE_VALIDO.fullmatch(autorizado):  # también evita que '..' o '/' saquen la carpeta de grabaciones
        return fallido('dominio inválido: %s' % repr(dominio)[:100])
    try:
        cliente = recolector.crear_cliente(modo, autorizado)
        res = recolector.recolectar(autorizado, cliente, ahora=ahora, propios=propios)
    except Exception as e:  # un recolector con errores no tumba el escaneo
        return fallido(_texto_error(e), getattr(cliente, 'consultas', 0))
    if not isinstance(res, Resultado):
        return fallido('el recolector no devolvió un Resultado', getattr(cliente, 'consultas', 0))
    try:
        res.fuente = res.fuente or fuente
        errores = validar(res, codigos)
        if res.dominio != autorizado or res.fuente != fuente:
            errores.insert(0, 'el resultado es de %s en %s y se pidió %s en %s' % (res.fuente, res.dominio, fuente, autorizado))
        if not errores:
            res = filtrar_alcance(res)
    except Exception as e:  # un resultado mal formado tampoco tumba el escaneo
        errores = [_texto_error(e)]
    if errores:
        return fallido('no cumple el contrato: ' + '. '.join(errores[:5]), getattr(res, 'consultas', 0))
    return res


def siguiente_estado(estado, intento, ahora):
    """(status, attempt, next_retry_at) de scan_source_runs después de una corrida.

    Una corrida fallida se reintenta a 1, 5 y 25 minutos. Después del cuarto intento (attempt = 3)
    queda en 'failed' y el escaneo termina como 'partial' (#23).
    """
    if estado == 'succeeded':
        return 'succeeded', intento, None
    if intento < MAX_INTENTO:
        return 'retrying', intento + 1, ahora + ESPERAS_REINTENTO[intento]
    return 'failed', intento, None


def con_reintentos(funcion, intentos=3, esperas=(5, 15), errores=(OSError, ValueError, http.client.HTTPException),
                   dormir=time.sleep):
    """Hasta `intentos` intentos dentro de una corrida, para fallas de segundos (por ejemplo un 502 pasajero).

    Un error HTTP 4xx, salvo 408 y 429, sale tal cual sin reintentar: la fuente sí respondió (por ejemplo un
    404 de HIBP es «sin brechas» y un 403 es «sin permiso»), y lo interpreta el recolector.
    """
    ultimo = None
    for n in range(intentos):
        try:
            return funcion()
        except errores as e:
            if isinstance(e, urllib.error.HTTPError) and e.code < 500 and e.code not in (408, 429):
                raise
            ultimo = e
            if n < intentos - 1:
                dormir(esperas[min(n, len(esperas) - 1)])
    raise FuenteNoResponde('%s después de %d intentos (%s: %s)' % (getattr(funcion, '__name__', 'consulta'), intentos,
                                                                  type(ultimo).__name__, ultimo))


# ---------------------------------------------------------------- respuestas grabadas

def fecha_iso(texto):
    d = datetime.fromisoformat(texto.replace('Z', ''))
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d


def nombre_archivo(consulta):
    """Nombre de archivo seguro para una consulta."""
    return '%s.json' % (re.sub(r'[^a-z0-9.-]+', '_', consulta.lower()).strip('_.') or 'vacio')


class Grabadora:
    """Graba y reproduce las respuestas de una fuente para un dominio.

    Cada respuesta es un archivo {grabado, consulta, datos} en la carpeta del dominio. La fecha va dentro
    del archivo porque git y las copias cambian la del sistema. Modos:
    - 'vivo': no toca el disco.
    - 'grabar': guarda cada respuesta. Con `nueva`, vacía la carpeta y escribe la marca de inicio con la
      primera respuesta válida, así una grabación fallida deja intacta la anterior. Si no se pudo vaciar
      la carpeta, el siguiente guardado lo vuelve a intentar. Con `completar`,
      reutiliza lo grabado desde `desde` y vuelve a consultar lo demás.
    - 'reproducir': solo lee del disco y lanza SinGrabacion si falta una respuesta.
    """

    def __init__(self, carpeta, modo='vivo', completar=False, desde=None, nueva=False, reloj=None, nombre=nombre_archivo):
        assert modo in MODOS, modo
        assert not completar or modo == 'grabar', 'completar solo aplica al grabar'
        self.carpeta, self.modo, self.completar, self.desde = Path(carpeta), modo, completar, desde
        self.nueva = nueva and modo == 'grabar'
        self.reloj = reloj or (lambda: datetime.now(timezone.utc))
        self.nombre = nombre
        self.leidas = []           # (archivo, fecha de grabación) de cada respuesta tomada del disco

    def archivo(self, consulta):
        return self.carpeta / self.nombre(consulta)

    @staticmethod
    def abrir(archivo):
        """(datos, fecha de grabación). El formato anterior (solo los datos) usa la fecha del sistema."""
        contenido = json.loads(archivo.read_text(encoding='utf-8') or '[]')
        if isinstance(contenido, dict) and 'datos' in contenido:
            return contenido['datos'], fecha_iso(contenido['grabado'])
        return contenido, datetime.fromtimestamp(archivo.stat().st_mtime, timezone.utc)

    def de_disco(self, consulta):
        """(True, datos) si la respuesta sale del disco, (False, None) si hay que consultar la fuente."""
        archivo = self.archivo(consulta)
        if self.modo == 'reproducir':
            if not archivo.exists():
                raise SinGrabacion(SIN_GRABACION + consulta)
            datos, fecha = self.abrir(archivo)
            self.leidas.append((archivo.name, fecha))
            return True, datos
        if self.completar and archivo.exists():
            datos, fecha = self.abrir(archivo)
            if self.desde is None or fecha >= self.desde:
                self.leidas.append((archivo.name, fecha))
                return True, datos
        return False, None

    def guardar(self, consulta, datos):
        if self.modo != 'grabar':
            return
        fecha = self.reloj().isoformat()  # la misma para la marca y la primera respuesta
        contenido = json.dumps({'grabado': fecha, 'consulta': consulta, 'datos': datos},
                               ensure_ascii=False).encode('utf-8')  # si no se puede guardar, falla antes de tocar la carpeta
        self.carpeta.mkdir(parents=True, exist_ok=True)
        if self.nueva:  # la fuente ya respondió: hasta aquí no se toca la grabación anterior
            for viejo in self.carpeta.glob('*.json'):
                viejo.unlink()
            (self.carpeta / MARCA).write_text(fecha, encoding='utf-8')
            self.nueva = False  # solo cuando ya se vació la carpeta y quedó la marca
        self.archivo(consulta).write_bytes(contenido)

    def descartar(self, consulta):
        """Una consulta que falló al grabar no deja pasar la respuesta de una grabación anterior."""
        archivo = self.archivo(consulta)
        if self.modo == 'grabar' and not self.nueva and archivo.exists():
            archivo.unlink()

    @staticmethod
    def inicio(carpeta):
        """Fecha de la marca de inicio de la grabación en curso, o None si no hay."""
        marca = Path(carpeta) / MARCA
        return fecha_iso(marca.read_text(encoding='utf-8').strip()) if marca.exists() else None

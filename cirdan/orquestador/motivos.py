"""Motivos de falla de un escaneo y de sus fuentes (RC-300).

En scans.stats.error y en scan_source_runs.error solo se guarda un motivo de MOTIVOS, con el código HTTP como número
si lo hay ('no respondió (HTTP 503)'). Nunca el texto de una excepción: uno de PostgreSQL trae tabla, restricción y a
veces los valores de la fila, y uno de una fuente trae lo que ella quiso mandar. El texto completo va al log de la API
con el id del escaneo (lo escribe el orquestador).

`motivo()` convierte el texto que dejó un recolector o una excepción en uno de MOTIVOS. `publico()` es lo que devuelven
GET /api/v1/scans y /scans/{id}: un texto guardado que no es un motivo (las filas de antes de RC-300) sale como
'error interno', sin migración (decisión 1 a de RC-300).
Sin imports de cirdan: lo usan el orquestador y la API.
"""
import re

NO_RESPONDIO = 'no respondió'
SIN_CUPO = 'sin cupo'
ILEGIBLE = 'respuesta que no se puede leer'
PLAZO = 'plazo vencido'
RECHAZADA = 'consulta rechazada'
NO_AUTORIZADA = 'no autorizada por la carta'
INTERRUMPIDO = 'escaneo interrumpido'
INTERNO = 'error interno'
MOTIVOS = (NO_RESPONDIO, SIN_CUPO, ILEGIBLE, PLAZO, RECHAZADA, NO_AUTORIZADA, INTERRUMPIDO, INTERNO)

# Un motivo, solo o con su código HTTP. Es lo único que publico() deja pasar.
PATRON = re.compile('(?:%s)(?: \\(HTTP [1-5][0-9]{2}\\))?' % '|'.join(re.escape(m) for m in MOTIVOS))

# El código HTTP que dejan los recolectores: 'HTTP 503' (crt.sh y Cert Spotter), 'HTTP Error 503' (str de un HTTPError
# de urllib), '(429, Retry-After' y 'respondió 403' (Shodan).
_HTTP = re.compile(r'\bHTTP(?: Error)? ([1-5][0-9]{2})\b|\(([1-5][0-9]{2}), Retry-After|respondió ([1-5][0-9]{2})\b')
# Errores de la base o del driver: siempre 'error interno', aunque su texto (que puede traer valores de una fila)
# diga otra cosa. _texto_error de contrato.py y el orquestador ponen el nombre de la clase primero.
_BASE = re.compile(r'^\s*(?:psycopg[\w.]*|\w*(?:Violation|DatabaseError|OperationalError|ProgrammingError|InterfaceError'
                   r'|DataError|IntegrityError|InternalError|NotSupportedError|InFailedSqlTransaction|LockNotAvailable'
                   r'|QueryCanceled|DeadlockDetected|SerializationFailure))\b')
_ILEGIBLE = ('que no se puede leer', 'recursionerror', 'jsondecodeerror', 'respuestailegible', 'unicodedecodeerror',
             'respuestagrande', 'pasó de su tope', 'respondió sin cuerpo', 'respondió null', 'respuesta inesperada',
             'forma inesperada', 'grabaciondanada')
_PLAZO = ('no quedó tiempo', 'se acabó el tiempo', 'sintiempo', 'plazovencido')
_NO_RESPONDIO = ('no respondió', 'no responde', 'timed out', 'timeout', 'tardó más de', 'urlerror', 'connectionerror',
                 'connection', 'conexión', 'remotedisconnected', 'incompleteread', 'httpexception', 'oserror',
                 'socket', 'fuentenoresponde', 'httperror')


def _con_codigo(motivo, codigo):
    return '%s (HTTP %d)' % (motivo, codigo) if codigo else motivo


def _codigo(texto):
    hallado = _HTTP.search(texto)
    return int(next(g for g in hallado.groups() if g)) if hallado else None


def motivo(texto):
    """El motivo de MOTIVOS para el texto de una falla. None si no hay falla (None o '')."""
    if texto is None or texto == '':
        return None
    if not isinstance(texto, str):
        return INTERNO
    if PATRON.fullmatch(texto):
        return texto
    if _BASE.match(texto):
        return INTERNO
    t = texto.lower()
    if t.startswith('el escaneo se cortó'):  # el texto de abandono de antes de RC-300
        return INTERRUMPIDO
    if 'sin cupo diario' in t:
        return SIN_CUPO
    if 'no autorizada por la carta' in t:
        return NO_AUTORIZADA
    codigo = _codigo(texto)
    if codigo == 429 or 'límite de consultas' in t or 'limitealcanzado' in t:
        return _con_codigo(SIN_CUPO, 429)
    if any(m in t for m in _ILEGIBLE):
        return _con_codigo(ILEGIBLE, codigo)
    if any(m in t for m in _PLAZO):
        return PLAZO
    if codigo and codigo >= 500:
        return _con_codigo(NO_RESPONDIO, codigo)
    if codigo and codigo >= 400:
        return _con_codigo(RECHAZADA, codigo)
    if any(m in t for m in _NO_RESPONDIO):
        return _con_codigo(NO_RESPONDIO, codigo)
    return INTERNO


def publico(texto):
    """Lo que las rutas de escaneos muestran de un error guardado: el motivo si es uno de MOTIVOS y 'error interno'
    si no. None y '' se quedan igual: no hubo error."""
    if texto is None or texto == '':
        return texto
    return texto if isinstance(texto, str) and PATRON.fullmatch(texto) else INTERNO

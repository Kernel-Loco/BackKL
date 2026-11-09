"""Vulnerabilidad conocida (known_vulnerability) por el CPE y la versión, con la API 2.0 de la NVD, sin red
(#18, RC-46).

No es un recolector y no hace peticiones: la visita web pide a la NVD las CVE del CPE con la versión de cada
tecnología (url(), con cpeName e isVulnerable) y le pasa la respuesta a revisar() junto con la tecnología que dio
huellas.analizar(). Las pruebas usan respuestas armadas a mano (pruebas/fixtures/huellas/) y nunca la API. Sin llave,
la NVD permite 5 peticiones cada 30 s: PAUSA_NVD entre una y otra.

Cómo decide:
- Solo tecnologías con CPE de las huellas, con versión de una huella que el sitio mostró (no implicada por otra) y
  confianza 100. Sin eso da 'sin_version'. Una versión que no cabe en un CPE (cpe_con_version) también.
- Solo una versión con al menos 3 partes numéricas (X.Y.Z), salvo los productos de DOS_PARTES, cuyas versiones
  normales tienen 2 (WordPress 6.4, Drupal 7.98, Django 4.2, IIS 10.0, thttpd 2.29, Quick.CMS 6.7, Prototype 1.7,
  Lift 2.6, GlassFish 4.1 y HP iLO 1.30). Con menos partes cpe_con_version() da None, así que url() nunca se
  arma para ellas, y revisar() da 'sin_version': 'Drupal 7', 'Apache/2.4', 'PHP/7' o 'nginx/1' no dicen qué versión
  es, y la NVD daría las CVE de un rango que calce con ese número o ninguna, y las dos cosas serían falsas.
- Nunca una versión con marca de distribución, como 'nginx/1.24.0 (Ubuntu)' (huellas.py, 'distribucion'): la
  distribución corrige las CVE en su propio paquete y la NVD no lo ve, así que todas saldrían aunque ya estén
  corregidas. Da 'distribucion' y ningún hallazgo, igual que soporte.py. Una versión sin marca de un producto que
  Debian o RHEL empaquetan sin marca, como 'nginx/1.18.0' (huellas.EMPAQUETAN_SIN_MARCA), sí da hallazgos, con
  'origen_sin_confirmar' True en la evidencia: la cabecera no dice si es de la distribución, que pudo corregir la
  CVE sin cambiar el número, o de una compilación propia (el texto revisado de known_vulnerability ya lo advierte).
  El valor sale de huellas.origen_sin_confirmar().
- Una CVE por hallazgo, normalizada con shodan._cve, con la clave 'CVE|vendor:producto' del CPE (clave(), por
  ejemplo 'CVE-2020-11022|jquery:jquery'), estable entre corridas: dos tecnologías del mismo sitio con la misma CVE,
  como Drupal y el jQuery que trae, son dos hallazgos y no chocan en contrato.validar. Las rechazadas (vulnStatus
  Rejected) no cuentan. Hasta MAX_CVE por tecnología, las más recientes por año y número; las demás van en
  'omitidas' para el aviso y no se cierran. Si la NVD tiene más resultados que los de la página, 'completa' es False.
- Sin una respuesta que se pueda leer da 'sin_dato': no se sabe, nunca 0 CVE. También sin ninguna CVE si la
  respuesta no está completa (más resultados que los de la página) o si se tiró alguna entrada que no se pudo leer
  (sin 'cve' o con un id que no es una CVE): 'sin_cve' solo sale de una respuesta completa y leída entera. Con CVE
  da 'con_cve', y 'completa' dice si faltó algo.
'cves' trae una fila por CVE para la tabla cves con 5 de sus columnas y ninguna llave más (COLUMNAS_CVES: cve_id,
description, cvss_base_score, cvss_vector y published_at), sin EPSS ni KEV, que son del cargador diario (#69,
RC-127). published_at lleva su zona: la NVD da la hora en UTC sin zona y aquí se le pone '+00:00', porque
cves.published_at es timestamptz y cirdan/db.py fija la zona de México en cada transacción (sin zona quedaría 6 h
corrida). Si la NVD ya trae zona, se respeta. Una fecha que no existe o una zona de más de 14 h dan None
(_publicada). La métrica de CVSS que se usó (cvss_metrica) va solo en la evidencia del hallazgo. Guardarlas en cves
y llenar findings.cve_id lo hace el orquestador cuando se conecte la visita web, no este módulo. Las filas de 'cves'
de varias tecnologías del mismo sitio pueden repetirse (la misma CVE de Drupal y de jQuery): la visita las une por
cve_id antes de guardarlas, porque cve_id es la llave de la tabla.
"""
import re
from datetime import datetime, timedelta
from urllib.parse import quote

from cirdan.recolectores import huellas, shodan

CODIGOS = {'known_vulnerability': 'medium'}   # la severidad del catálogo (semilla 004), la misma que shodan.py
URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&isVulnerable&noRejected'
NOMBRE_FUENTE = 'NVD'
PAUSA_NVD = 6                # segundos entre peticiones sin llave (5 cada 30 s)
MIN_CONFIANZA = 100
MAX_CVE = shodan.MAX_CVE     # por tecnología, como por IP en shodan.py
MAX_DESCRIPCION = 2000       # caracteres de la descripción en inglés de la NVD que van a cves.description
METRICAS = ('cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2')   # la primera que traiga la CVE
TITULO = 'Vulnerabilidad conocida %s por la versión de %s %s en %s'
ESTADOS = ('con_cve', 'sin_cve', 'sin_dato', 'distribucion', 'sin_version')
COLUMNAS_CVES = ('cve_id', 'description', 'cvss_base_score', 'cvss_vector', 'published_at')   # de la tabla cves

# cpe:2.3:part:vendor:product:version:... con 13 partes, en la forma de cadena de CPE 2.3 (NISTIR 7695, 6.2): cada
# parte es '*', '-' o letras, dígitos, '.', '_' y '-', con '?' o '*' al inicio o al final, y cualquier otro signo
# ASCII va escapado con '\' (como 'cms_core_\&_grid'). Un espacio, un '&' sin escapar o algo que no es ASCII no
# pasan. La versión de las huellas solo lleva los caracteres de _VERSION.
_PARTE = r'(?:\*|-|(?:\?+|\*)?(?:[a-z0-9._-]|\\[!-/:-@\[-`{-~])+(?:\?+|\*)?)'
_CPE = re.compile(r'cpe:2\.3:[aho](?::%s){10}' % _PARTE, re.I | re.A)
_VERSION = re.compile(r'[0-9][0-9a-z._-]{0,30}', re.I | re.A)
# La fecha de la NVD, con su zona si la trae (grupo 2). Que sea una fecha y hora que existe lo revisa _publicada.
_FECHA = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?)(Z|[+-][0-9]{2}:[0-5][0-9])?',
                    re.A)
MAX_ZONA = timedelta(hours=14)   # se aceptan de -14:00 a +14:00: las que existen van de -12:00 a +14:00
MIN_PARTES = 3                   # partes numéricas de la versión que se consulta (X.Y.Z)
# vendor:producto del CPE -> las versiones de 2 partes que sí son una versión normal de ese producto. Drupal solo
# hasta la 7 (7.98): desde la 8 son de 3 (10.2.3), y 'Drupal 10.2' es una rama.
DOS_PARTES = {'acme:thttpd': r'\d+\.\d+', 'djangoproject:django': r'\d+\.\d+', 'drupal:drupal': r'[5-7]\.\d+',
              'hp:integrated_lights-out': r'\d+\.\d+', 'liftweb:lift': r'\d+\.\d+',
              'microsoft:internet_information_server': r'\d+\.\d+', 'opensolution:quick.cms': r'\d+\.\d+',
              'oracle:glassfish_server': r'\d+\.\d+', 'prototypejs:prototype': r'\d+\.\d+',
              'wordpress:wordpress': r'\d+\.\d+'}
_NUMERICA = re.compile(r'[0-9]+(?:\.[0-9]+)*', re.A)   # la parte numérica de la versión: 1.18.0 de 1.18.0-beta


def cpe_con_version(cpe, version):
    """El CPE de las huellas (con '*' en la versión) con la versión puesta en minúsculas, o None. _VERSION solo deja
    letras, dígitos, '.', '_' y '-', que no se escapan en un CPE 2.3 (el '-' solo, sin más, querría decir 'no
    aplica', pero _VERSION pide un dígito al inicio). Un CPE que no es una cadena de CPE 2.3 bien formada (_CPE) da
    None, y uno con un ':' escapado tampoco tiene 13 partes. Los espacios de las orillas se quitan antes: el de GLPI
    en huellas_wappalyzer.json termina en un espacio. Con los datos de Wappalyzer 6.10.54 quedan sin CPE válido 3 de
    136, que nunca se consultan: Angular (14 partes), Erlang ('erlang%2fotp', con el '%' sin escapar) y Weblication
    ('cms_core_&_grid', con el '&' sin escapar) (pruebas/test_huellas.py, CPE_INVALIDOS). Una versión sin precisión
    (con_precision(), como 'Drupal 7' o 'nginx/1') también da None, así que url() nunca se arma para ella."""
    if isinstance(cpe, str):
        cpe = cpe.strip(' \t')
    if not (isinstance(cpe, str) and _CPE.fullmatch(cpe) and isinstance(version, str) and _VERSION.fullmatch(version)):
        return None
    partes = cpe.split(':')
    if len(partes) != 13 or partes[5] != '*':
        return None
    partes[5] = version.lower()
    return ':'.join(partes) if con_precision(cpe, version) else None


def _producto(cpe):
    """'vendor:producto' de un CPE 2.3, en minúsculas."""
    return ':'.join(cpe.split(':')[3:5]).lower()


def con_precision(cpe, version):
    """True si la versión tiene al menos MIN_PARTES partes numéricas, o 2 que DOS_PARTES acepta para el producto del
    CPE: '1.18.0' y 'WordPress 6.4' sí, '2.4', '7' y 'Drupal 10.2' no."""
    m = _NUMERICA.match(version) if isinstance(version, str) and isinstance(cpe, str) else None
    if not m:
        return False
    partes = m.group(0).count('.') + 1
    dos = DOS_PARTES.get(_producto(cpe))
    return partes >= MIN_PARTES or (partes == 2 and dos is not None and re.fullmatch(dos, m.group(0), re.A) is not None)


def clave(cve_id, cpe):
    """La clave del hallazgo: la CVE y el producto del CPE, 'CVE-2020-11022|jquery:jquery'. No lleva la versión, así
    que es la misma entre corridas aunque el sitio cambie de versión dentro de las afectadas."""
    return '%s|%s' % (cve_id, _producto(cpe))


def url(cpe):
    """La URL de la API 2.0 de la NVD para un CPE con versión, o None si el CPE no es una cadena (como el None de
    cpe_con_version())."""
    return URL % quote(cpe, safe=':*.-_') if isinstance(cpe, str) else None


def _numero(x, tope):
    return float(x) if isinstance(x, (int, float)) and not isinstance(x, bool) and 0 <= x <= tope else None


def _cvss(metricas):
    """(puntaje, vector, versión de la métrica) de la primera de METRICAS, prefiriendo la de la NVD (Primary)."""
    if not isinstance(metricas, dict):
        return None, None, None
    for clave in METRICAS:
        lista = [m for m in metricas.get(clave) or () if isinstance(m, dict) and isinstance(m.get('cvssData'), dict)]
        lista.sort(key=lambda m: m.get('type') != 'Primary')
        for m in lista:
            puntaje = _numero(m['cvssData'].get('baseScore'), 10)
            if puntaje is not None:
                vector = m['cvssData'].get('vectorString')
                return round(puntaje, 1), vector if isinstance(vector, str) else None, clave
    return None, None, None


def _descripcion(descripciones):
    for d in descripciones if isinstance(descripciones, list) else ():
        if isinstance(d, dict) and d.get('lang') == 'en' and isinstance(d.get('value'), str):
            return d['value'][:MAX_DESCRIPCION]
    return None


def _publicada(x):
    """La fecha de publicación con su zona, o None: sin zona es UTC y lleva '+00:00'. Solo una fecha y hora que
    existe (datetime.fromisoformat sin error: '2021-02-30T25:61:00' no) y con la zona entre -14:00 y +14:00, las que
    existen ('+99:99' no): Postgres rechaza una fecha imposible en cves.published_at, y con ella todo el lote."""
    m = _FECHA.fullmatch(x) if isinstance(x, str) else None
    if not m:
        return None
    salida = m.group(0) if m.group(2) else m.group(1) + '+00:00'
    try:
        fecha = datetime.fromisoformat(salida)
    except ValueError:
        return None
    return salida if abs(fecha.utcoffset()) <= MAX_ZONA else None


def leer(respuesta):
    """{'cves': [filas para la tabla cves con solo COLUMNAS_CVES, de la más reciente a la más vieja], 'metricas':
    {cve_id: la de METRICAS que dio el puntaje, o None}, 'descartadas': las entradas que no se pudieron leer,
    'completa'} de una respuesta de la API 2.0, o None si no se puede leer. Sin repetir ni rechazadas. 'completa' es
    False si la NVD tiene más resultados que los de la página o si se descartó alguna entrada."""
    if not isinstance(respuesta, dict) or not isinstance(respuesta.get('vulnerabilities'), list):
        return None
    filas, metricas, descartadas = {}, {}, 0
    for v in respuesta['vulnerabilities']:
        cve = v.get('cve') if isinstance(v, dict) else None
        if not isinstance(cve, dict):
            descartadas += 1
            continue
        if cve.get('vulnStatus') == 'Rejected':
            continue
        cve_id = shodan._cve(cve.get('id'))
        if not cve_id:
            descartadas += 1
            continue
        if cve_id in filas:
            continue
        puntaje, vector, metrica = _cvss(cve.get('metrics'))
        filas[cve_id] = {'cve_id': cve_id, 'description': _descripcion(cve.get('descriptions')),
                         'cvss_base_score': puntaje, 'cvss_vector': vector,
                         'published_at': _publicada(cve.get('published'))}
        metricas[cve_id] = metrica
    total, inicio = respuesta.get('totalResults'), respuesta.get('startIndex', 0)
    leidas = len(respuesta['vulnerabilities'])
    completa = isinstance(total, int) and isinstance(inicio, int) and inicio == 0 and total <= leidas \
        and not descartadas
    orden = sorted(filas, key=lambda c: tuple(int(n) for n in c.split('-')[1:]), reverse=True)
    return {'cves': [filas[c] for c in orden], 'metricas': metricas, 'descartadas': descartadas,
            'completa': completa}


def revisar(tecnologia, respuesta, host):
    """{'estado' (de ESTADOS), 'cpe' (con la versión), 'hallazgos', 'omitidas', 'cves' (filas para la tabla cves de
    los hallazgos), 'completa'} de una tecnología de huellas.analizar() con la respuesta de la NVD de su CPE. Sin
    ninguna CVE y con una respuesta incompleta da 'sin_dato', nunca 'sin_cve'."""
    t = tecnologia if isinstance(tecnologia, dict) else {}
    salida = {'estado': 'sin_version', 'cpe': None, 'hallazgos': [], 'omitidas': [], 'cves': [], 'completa': False}
    cpe = cpe_con_version(t.get('cpe'), t.get('version'))
    if not cpe or t.get('implicada_por') or not isinstance(t.get('confianza'), int) \
            or t['confianza'] < MIN_CONFIANZA:
        return salida
    salida['cpe'] = cpe
    if t.get('distribucion'):
        return dict(salida, estado='distribucion')
    leidas = leer(respuesta)
    if leidas is None:
        return dict(salida, estado='sin_dato')
    filas = leidas['cves']
    hallazgos = []
    for fila in filas[:MAX_CVE]:
        titulo = TITULO % (fila['cve_id'], t['nombre'], t['version'], host)
        evidencia = {'title': titulo, 'cve': fila['cve_id'], 'cpe': cpe, 'tecnologia': t['nombre'],
                     'version': t['version'], 'cvss': fila['cvss_base_score'],
                     'cvss_metrica': leidas['metricas'][fila['cve_id']],
                     'senales': list(t.get('senales') or []), 'deducida_por_version': True,
                     'origen_sin_confirmar': huellas.origen_sin_confirmar(t),
                     'fuente_datos': NOMBRE_FUENTE, 'host': host}
        hallazgos.append({'codigo': 'known_vulnerability', 'severidad': CODIGOS['known_vulnerability'],
                          'clave': clave(fila['cve_id'], cpe), 'titulo': titulo, 'evidencia': evidencia})
    estado = 'con_cve' if hallazgos else 'sin_cve' if leidas['completa'] else 'sin_dato'
    return dict(salida, estado=estado, hallazgos=hallazgos,
                omitidas=[f['cve_id'] for f in filas[MAX_CVE:]], cves=filas[:MAX_CVE], completa=leidas['completa'])

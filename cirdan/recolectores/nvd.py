"""Vulnerabilidad conocida (known_vulnerability) por el CPE y la versión, con la API 2.0 de la NVD, sin red
(#18, RC-46).

No es un recolector y no hace peticiones: la visita web pide a la NVD las CVE del CPE con la versión de cada
tecnología (url(), con cpeName e isVulnerable) y le pasa la respuesta a revisar() junto con la tecnología que dio
huellas.analizar(). Las pruebas usan respuestas armadas a mano (pruebas/fixtures/huellas/) y nunca la API. Sin llave,
la NVD permite 5 peticiones cada 30 s: PAUSA_NVD entre una y otra.

Cómo decide:
- Solo tecnologías con CPE de las huellas, con versión de una huella que el sitio mostró (no implicada por otra) y
  confianza 100. Sin eso da 'sin_version'. Una versión que no cabe en un CPE (cpe_con_version) también.
- Nunca una versión de una distribución, como 'nginx/1.24.0 (Ubuntu)' (huellas.py, 'distribucion'): la distribución
  corrige las CVE en su propio paquete y la NVD no lo ve, así que todas saldrían aunque ya estén corregidas. Da
  'distribucion' y ningún hallazgo, igual que soporte.py.
- Una CVE por hallazgo, con la CVE como clave, como shodan.hallazgo_cve, normalizada con shodan._cve. Las rechazadas
  (vulnStatus Rejected) no cuentan. Hasta MAX_CVE por tecnología, las más recientes por año y número; las demás van en
  'omitidas' para el aviso y no se cierran. Si la NVD tiene más resultados que los de la página, 'completa' es False.
- Sin una respuesta que se pueda leer da 'sin_dato': no se sabe, nunca 0 CVE.
'cves' trae una fila por CVE para la tabla cves (cve_id, description, cvss_base_score, cvss_vector y published_at),
sin EPSS ni KEV, que son del cargador diario (#69, RC-127). Guardarlas en cves y llenar findings.cve_id lo hace el
orquestador cuando se conecte la visita web, no este módulo.
"""
import re
from urllib.parse import quote

from cirdan.recolectores import shodan

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

# cpe:2.3:part:vendor:product:version:... con 13 partes. La versión de las huellas solo lleva estos caracteres.
_CPE = re.compile(r'cpe:2\.3:[aho](?::(?:[^:\\]|\\.)*){10}')
_VERSION = re.compile(r'[0-9][0-9a-z._-]{0,30}', re.I | re.A)
_FECHA = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?')


def cpe_con_version(cpe, version):
    """El CPE de las huellas (con '*' en la versión) con la versión puesta en minúsculas, o None. _VERSION solo deja
    letras, dígitos, '.', '_' y '-', que no se escapan en un CPE 2.3 (el '-' solo, sin más, querría decir 'no
    aplica', pero _VERSION pide un dígito al inicio). Un CPE con un ':' escapado no tiene 13 partes y da None."""
    if not (isinstance(cpe, str) and _CPE.fullmatch(cpe) and isinstance(version, str) and _VERSION.fullmatch(version)):
        return None
    partes = cpe.split(':')
    if len(partes) != 13 or partes[5] != '*':
        return None
    partes[5] = version.lower()
    return ':'.join(partes)


def url(cpe):
    """La URL de la API 2.0 de la NVD para un CPE con versión."""
    return URL % quote(cpe, safe=':*.-_')


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


def leer(respuesta):
    """{'cves': [filas para la tabla cves, de la más reciente a la más vieja], 'completa'} de una respuesta de la API
    2.0, o None si no se puede leer. Sin repetir ni rechazadas."""
    if not isinstance(respuesta, dict) or not isinstance(respuesta.get('vulnerabilities'), list):
        return None
    filas = {}
    for v in respuesta['vulnerabilities']:
        cve = v.get('cve') if isinstance(v, dict) else None
        if not isinstance(cve, dict) or cve.get('vulnStatus') == 'Rejected':
            continue
        cve_id = shodan._cve(cve.get('id'))
        if not cve_id or cve_id in filas:
            continue
        puntaje, vector, metrica = _cvss(cve.get('metrics'))
        publicada = cve.get('published')
        filas[cve_id] = {'cve_id': cve_id, 'description': _descripcion(cve.get('descriptions')),
                         'cvss_base_score': puntaje, 'cvss_vector': vector, 'cvss_metrica': metrica,
                         'published_at': publicada if isinstance(publicada, str) and _FECHA.fullmatch(publicada)
                         else None}
    total, inicio = respuesta.get('totalResults'), respuesta.get('startIndex', 0)
    leidas = len(respuesta['vulnerabilities'])
    completa = isinstance(total, int) and isinstance(inicio, int) and inicio == 0 and total <= leidas
    orden = sorted(filas, key=lambda c: tuple(int(n) for n in c.split('-')[1:]), reverse=True)
    return {'cves': [filas[c] for c in orden], 'completa': completa}


def revisar(tecnologia, respuesta, host):
    """{'estado' (de ESTADOS), 'cpe' (con la versión), 'hallazgos', 'omitidas', 'cves' (filas para la tabla cves de
    los hallazgos), 'completa'} de una tecnología de huellas.analizar() con la respuesta de la NVD de su CPE."""
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
                     'version': t['version'], 'cvss': fila['cvss_base_score'], 'cvss_metrica': fila['cvss_metrica'],
                     'senales': list(t.get('senales') or []), 'deducida_por_version': True,
                     'fuente_datos': NOMBRE_FUENTE, 'host': host}
        hallazgos.append({'codigo': 'known_vulnerability', 'severidad': CODIGOS['known_vulnerability'],
                          'clave': fila['cve_id'], 'titulo': titulo, 'evidencia': evidencia})
    return dict(salida, estado='con_cve' if hallazgos else 'sin_cve', hallazgos=hallazgos,
                omitidas=[f['cve_id'] for f in filas[MAX_CVE:]], cves=filas[:MAX_CVE], completa=leidas['completa'])

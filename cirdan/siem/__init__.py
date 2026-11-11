"""Salida a SIEM (#98, RC-212): eventos de LowTide en el formato del HTTP Event Collector (HEC) de Splunk,
con los nombres de campo del Common Information Model (CIM 8.5).

Un evento por hallazgo abierto (sourcetype lowtide:finding, modelo Vulnerabilities, y Alerts si es crítico
y nuevo o si subió a crítico),
uno del último escaneo (lowtide:scan), uno del último score (lowtide:score) y uno de la exportación (lowtide:export),
que sale siempre, aunque el dominio no tenga hallazgos. La app de Splunk splunk/lowtide_splunk/ les pone los eventtypes
y los tags del CIM.

Tiempo: todos los eventos de una exportación llevan como `time` el momento de la exportación y el mismo `export_id`.
Así un hallazgo que sigue abierto vuelve a entrar al periodo del tablero en cada exportación, y el tablero se queda con
la última exportación de cada dominio: un hallazgo que ya no viene en ella está resuelto. Los momentos del hallazgo,
del escaneo y del score van como campos (detected_at, scan_finished_at, finished_at y computed_at).

Minimización: ningún evento lleva la evidencia del hallazgo, el valor de un activo de tipo email, los
errores de las fuentes ni secretos. Los campos se eligen uno por uno, nunca se copia una fila o un JSON
completo. País y ASN no salen, así que no hace falta la atribución de DB-IP.
"""
import json
import re
from urllib.parse import urlsplit

from cirdan.score import criterio

VENDOR_PRODUCT = 'LowTide'
HOST = 'lowtide'
SOURCE = 'lowtide'
# Del JSON de scans.stats solo salen estas llaves (cirdan/orquestador/__init__.py, al cerrar el escaneo).
STATS = ('assets', 'findings', 'new_findings', 'resolved_findings', 'sources_ok', 'sources_failed')
# Un activo service es '<ip>:<puerto>/<protocolo>' (cirdan/recolectores/shodan.py). La IP puede ser IPv6.
SERVICIO = re.compile(r'^(?P<host>.+):(?P<puerto>[0-9]{1,5})/[a-z0-9-]+$')


def _iso(momento):
    return momento.isoformat() if momento is not None else None


def _sobre(sourcetype, ahora, export_id, evento):
    """Evento de HEC: `time` en segundos desde 1970 (el de la exportación) y los campos del CIM dentro de `event`."""
    if ahora.tzinfo is None:
        raise ValueError('el momento de la exportación necesita zona horaria')
    evento['export_id'] = export_id
    evento['exported_at'] = _iso(ahora)
    return {'time': round(ahora.timestamp(), 3), 'host': HOST, 'source': SOURCE,
            'sourcetype': sourcetype, 'event': evento}


def destino(dominio, h):
    """`dest` del CIM es un host o una IP: (dest, dest_port, url).

    Un correo nunca sale y su dest es el dominio. Un servicio da su IP y su puerto aparte, una documentación de API el
    host de su URL, y un certificado el nombre de su activo padre o, si no tiene, el dominio."""
    tipo, valor = h['asset_type'], h['asset']
    if tipo == 'email' or not valor:
        return dominio, None, None
    if tipo == 'service':
        m = SERVICIO.match(valor)
        host = h.get('asset_ip') or (m.group('host').strip('[]') if m else valor)
        return host, int(m.group('puerto')) if m else None, None
    if tipo == 'api_doc':
        return urlsplit(valor).hostname or dominio, None, valor
    if tipo == 'certificate':
        return h.get('asset_parent') or dominio, None, None
    return valor, None, None


def evento_hallazgo(dominio, h, ahora, export_id):
    """Un hallazgo abierto con los campos de CIM Vulnerabilities."""
    dest, puerto, url = destino(dominio, h)
    evento = {
        'vendor_product': VENDOR_PRODUCT, 'dvc': VENDOR_PRODUCT, 'app': VENDOR_PRODUCT,
        'signature': h['rule_title'], 'signature_id': h['rule_code'], 'severity': h['severity'],
        'category': h['category'], 'dest': dest, 'asset_type': h['asset_type'],
        'finding_id': h['id'], 'scan_id': h['last_scan_id'], 'domain': dominio, 'status': h['status'],
        'data_source': h['data_source'], 'detected_at': _iso(h['detected_at']),
        'scan_finished_at': _iso(h['scan_finished_at']), 'recurrence': h['recurrence'],
    }
    if puerto is not None:
        evento['dest_port'] = puerto
    if url:
        evento['url'] = url
    if h['cve_id']:
        evento['cve'] = h['cve_id']
    if h['cvss'] is not None:
        evento['cvss'] = float(h['cvss'])
    if h['attack_technique_id']:
        evento['mitre_technique_id'] = h['attack_technique_id']
    subio = h['previous_severity'] not in (None, 'critical')
    if h['severity'] == 'critical' and (h['recurrence'] == 'new' or subio):
        # CIM Alerts: el eventtype lowtide_alert solo toma los críticos nuevos (no aportaron a los dos últimos scores
        # de escaneo, cirdan/api/v1.py) y los que siguen abiertos pero no eran críticos en el más viejo de esos dos
        # scores (los subió el ML o el motor). Así uno que sigue abierto y crítico no vuelve a ser alerta en cada
        # escaneo, y uno que se reabre o sube sí. Dos exportaciones después del mismo escaneo la repiten: se deduplica
        # por finding_id. También alerta, y se repite, uno que subió a crítico sin un escaneo con fuentes (un score
        # rules_change o de un escaneo con sources_ok = 0) o porque el ML cayó a reglas: repite alertas, no las pierde.
        evento['type'] = 'alert'
    return _sobre('lowtide:finding', ahora, export_id, evento)


def evento_escaneo(dominio, s, ahora, export_id):
    """El último escaneo cerrado: estado, cobertura parcial y cómo terminó cada fuente, sin sus errores."""
    stats = s['stats'] or {}
    evento = {
        'vendor_product': VENDOR_PRODUCT, 'scan_id': s['id'], 'domain': dominio, 'status': s['status'],
        'trigger': s['trigger'], 'queued_at': _iso(s['queued_at']), 'finished_at': _iso(s['finished_at']),
        # Como el score del mismo escaneo (orquestador, al cerrar): failed también es cobertura parcial.
        'partial_coverage': s['status'] != 'completed',
        **{k: stats.get(k) for k in STATS},
        'rules_without_coverage': list(stats.get('rules_without_coverage') or []),
        'sources_partial': list(stats.get('sources_partial') or []),
        'source_runs': [{'data_source': r['data_source'], 'status': r['status']} for r in s['sources']],
    }
    return _sobre('lowtide:scan', ahora, export_id, evento)


def evento_score(dominio, sc, ahora, export_id):
    """El último score con su banda y el score de cada categoría."""
    evento = {
        'vendor_product': VENDOR_PRODUCT, 'score_id': sc['id'], 'scan_id': sc['scan_id'], 'domain': dominio,
        'score': sc['score'], 'band': criterio.banda(sc['score']), 'method': sc['method'],
        'model_version': sc['model_version'], 'rule_set_version': sc['rule_set_version'], 'reason': sc['reason'],
        'partial_coverage': sc['partial_coverage'], 'computed_at': _iso(sc['computed_at']),
        **{'score_' + c: sc['category_scores'].get(c) for c in criterio.CATEGORIAS},
    }
    return _sobre('lowtide:score', ahora, export_id, evento)


def evento_exportacion(dominio, hallazgos, escaneo, score, ahora, export_id):
    """Marca la exportación del dominio: el tablero toma la última y, si no trae hallazgos, el dominio tiene 0."""
    evento = {
        'vendor_product': VENDOR_PRODUCT, 'domain': dominio, 'findings': len(hallazgos),
        'scan_id': escaneo['id'] if escaneo else None, 'score_id': score['id'] if score else None,
    }
    return _sobre('lowtide:export', ahora, export_id, evento)


def ndjson(dominio, hallazgos, escaneo=None, score=None, *, ahora, export_id):
    """Un evento de HEC por línea, listo para `POST /services/collector/event`. `ahora` es el momento de la exportación,
    con zona horaria, y `export_id` la identifica: los dos son iguales en todos los eventos."""
    eventos = [evento_hallazgo(dominio, h, ahora, export_id) for h in hallazgos]
    if escaneo:
        eventos.append(evento_escaneo(dominio, escaneo, ahora, export_id))
    if score:
        eventos.append(evento_score(dominio, score, ahora, export_id))
    eventos.append(evento_exportacion(dominio, hallazgos, escaneo, score, ahora, export_id))
    return ''.join(json.dumps(e, ensure_ascii=False, separators=(',', ':')) + '\n' for e in eventos)

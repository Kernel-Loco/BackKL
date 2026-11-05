"""Salida a SIEM (#98, RC-212): eventos de LowTide en el formato del HTTP Event Collector (HEC) de Splunk,
con los nombres de campo del Common Information Model (CIM 8.5).

Un evento por hallazgo abierto (sourcetype lowtide:finding, modelo Vulnerabilities, y Alerts si es crítico),
uno del último escaneo (lowtide:scan) y uno del último score (lowtide:score). La app de Splunk
splunk/lowtide_splunk/ les pone los eventtypes y los tags del CIM.

Minimización: ningún evento lleva la evidencia del hallazgo, el valor de un activo de tipo email, los
errores de las fuentes ni secretos. Los campos se eligen uno por uno, nunca se copia una fila o un JSON
completo. País y ASN no salen, así que no hace falta la atribución de DB-IP.
"""
import json

from cirdan.score import criterio

VENDOR_PRODUCT = 'LowTide'
HOST = 'lowtide'
SOURCE = 'lowtide'
# Del JSON de scans.stats solo salen estas llaves (cirdan/orquestador/__init__.py, al cerrar el escaneo).
STATS = ('assets', 'findings', 'new_findings', 'resolved_findings', 'sources_ok', 'sources_failed')


def _iso(momento):
    return momento.isoformat() if momento is not None else None


def _sobre(sourcetype, momento, evento):
    """Evento de HEC: `time` en segundos desde 1970 y los campos del CIM dentro de `event`."""
    if momento.tzinfo is None:
        raise ValueError('el momento del evento necesita zona horaria')
    return {'time': round(momento.timestamp(), 3), 'host': HOST, 'source': SOURCE,
            'sourcetype': sourcetype, 'event': evento}


def evento_hallazgo(dominio, h):
    """Un hallazgo abierto con los campos de CIM Vulnerabilities. `dest` de un correo es el dominio."""
    dest = h['asset'] if h['asset_type'] != 'email' and h['asset'] else dominio
    evento = {
        'vendor_product': VENDOR_PRODUCT, 'dvc': VENDOR_PRODUCT, 'app': VENDOR_PRODUCT,
        'signature': h['rule_title'], 'signature_id': h['rule_code'], 'severity': h['severity'],
        'category': h['category'], 'dest': dest, 'asset_type': h['asset_type'],
        'finding_id': h['id'], 'scan_id': h['last_scan_id'], 'domain': dominio, 'status': h['status'],
        'data_source': h['data_source'], 'detected_at': _iso(h['detected_at']),
    }
    if h['cve_id']:
        evento['cve'] = h['cve_id']
    if h['cvss'] is not None:
        evento['cvss'] = float(h['cvss'])
    if h['attack_technique_id']:
        evento['mitre_technique_id'] = h['attack_technique_id']
    if h['severity'] == 'critical':
        evento['type'] = 'alert'  # CIM Alerts: el eventtype lowtide_alert solo toma los críticos
    return _sobre('lowtide:finding', h['scan_finished_at'] or h['detected_at'], evento)


def evento_escaneo(dominio, s):
    """El último escaneo cerrado: estado, cobertura parcial y cómo terminó cada fuente, sin sus errores."""
    stats = s['stats'] or {}
    evento = {
        'vendor_product': VENDOR_PRODUCT, 'scan_id': s['id'], 'domain': dominio, 'status': s['status'],
        'trigger': s['trigger'], 'queued_at': _iso(s['queued_at']), 'finished_at': _iso(s['finished_at']),
        'partial_coverage': s['status'] == 'partial',
        **{k: stats.get(k) for k in STATS},
        'rules_without_coverage': list(stats.get('rules_without_coverage') or []),
        'sources_partial': list(stats.get('sources_partial') or []),
        'source_runs': [{'data_source': r['data_source'], 'status': r['status']} for r in s['sources']],
    }
    return _sobre('lowtide:scan', s['finished_at'] or s['queued_at'], evento)


def evento_score(dominio, sc):
    """El último score con su banda y el score de cada categoría."""
    evento = {
        'vendor_product': VENDOR_PRODUCT, 'score_id': sc['id'], 'scan_id': sc['scan_id'], 'domain': dominio,
        'score': sc['score'], 'band': criterio.banda(sc['score']), 'method': sc['method'],
        'model_version': sc['model_version'], 'rule_set_version': sc['rule_set_version'], 'reason': sc['reason'],
        'partial_coverage': sc['partial_coverage'], 'computed_at': _iso(sc['computed_at']),
        **{'score_' + c: sc['category_scores'].get(c) for c in criterio.CATEGORIAS},
    }
    return _sobre('lowtide:score', sc['computed_at'], evento)


def ndjson(dominio, hallazgos, escaneo=None, score=None):
    """Un evento de HEC por línea, listo para `POST /services/collector/event`."""
    eventos = [evento_hallazgo(dominio, h) for h in hallazgos]
    if escaneo:
        eventos.append(evento_escaneo(dominio, escaneo))
    if score:
        eventos.append(evento_score(dominio, score))
    return ''.join(json.dumps(e, ensure_ascii=False, separators=(',', ':')) + '\n' for e in eventos)

"""API v1 de lectura para el portal (RC-17), con la forma del contrato de docs/contrato_api_v1.md (#21).

Todo con sesión: la empresa sale de la cookie y RLS filtra en la base. Las bandas, el ponderado y
el piso salen del criterio de criticidad (cirdan/score/criterio.py, #29).
"""
import uuid
from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException

from cirdan import orquestador
from cirdan.auth.deps import Session, current_session, require_roles
from cirdan.orquestador.txt import esperado as txt_esperado
from cirdan.db import transaction
from cirdan.score import criterio, motor

router = APIRouter(prefix='/api/v1', tags=['portal'])
SEVERIDADES = ('critical', 'high', 'medium', 'low')

# ---------------------------------------------------------------- características del reto
# Desde #23 vienen guardadas en la evidencia. Para los hallazgos de la semilla, que no las traen, se calculan
# con las mismas reglas del contrato #21.
TIPO = {
    'breach_exposure': 'correos_en_brecha', 'cert_expired': 'certificado_vencido',
    'cert_expiring_soon': 'certificado_por_vencer', 'outdated_software': 'software_desactualizado',
    'exposed_rdp': 'servicio_expuesto', 'dmarc_missing': 'dmarc_faltante', 'spf_missing': 'spf_faltante',
    'lookalike_domain': 'dominio_parecido',
}
EXPOSICION_DIRECTA = {'outdated_software', 'exposed_rdp'}
SENSIBILIDAD = {'breach_exposure': 'alta', 'exposed_rdp': 'alta', 'spf_missing': 'baja'}

# El título, qué significa y qué hacer de cada regla salen de scoring_rule_texts (#30, migración 003).
# No hay respaldo: la llave foránea y los NOT NULL de la 003 obligan a que toda regla tenga los tres textos.
RESUMEN = {
    'critical': 'Es crítico porque alguien de fuera lo puede aprovechar ya, sin pasos extra, y obtener acceso a cuentas, sistemas o datos.',
    'high': 'Es alto porque es una exposición seria, aunque aprovecharla necesita otro paso o una condición.',
    'medium': 'Es medio porque facilita un ataque, como la suplantación, pero no da acceso por sí solo.',
    'low': 'Es bajo porque falta una buena práctica y el impacto es menor.',
}
# Etiquetas de factores de la semilla demo (en inglés) mientras el motor de score (#31) las escribe en español.
FACTOR_ES = {
    'Breach less than 6 months ago': 'La brecha es de hace menos de 6 meses',
    'Includes admin accounts': 'Incluye cuentas de administrador',
    'Breach includes passwords': 'La brecha incluye contraseñas',
    'Finding seen previously': 'El hallazgo ya se había visto antes',
}


def _dias(desde, hasta):
    if isinstance(desde, str):
        desde = date.fromisoformat(desde[:10])
    if isinstance(desde, datetime):
        desde = desde.date()
    if isinstance(hasta, datetime):
        hasta = hasta.date()
    return max(0, (hasta - desde).days)


def caracteristicas(f):
    if isinstance(f['evidence'].get('caracteristicas'), dict):
        return f['evidence']['caracteristicas']
    referencia = f['scan_at'] or f['detected_at']
    if f['rule_code'] == 'breach_exposure' and f['breach_date']:
        desde = f['breach_date']
    elif f['rule_code'] == 'cert_expired' and f['evidence'].get('not_after'):
        desde = f['evidence']['not_after']
    elif f['rule_code'] in EXPOSICION_DIRECTA:
        desde = f['asset_first_seen']
    else:
        desde = f['detected_at']
    return {
        'tipo': TIPO.get(f['rule_code'], f['rule_code']),
        'antiguedad_dias': _dias(desde, referencia),
        'exposicion': 'directa' if f['rule_code'] in EXPOSICION_DIRECTA or f['asset_type'] in ('ip', 'service') else 'publica',
        'sensibilidad': SENSIBILIDAD.get(f['rule_code'], 'media'),
    }


def _query(session, sql, params=()):
    with transaction(session.org_id) as conn:
        return conn.execute(sql, params).fetchall()


def _domain_id(session, fqdn):
    rows = _query(session, 'SELECT id::text FROM domains WHERE fqdn = %s', (fqdn,))
    if not rows:
        raise HTTPException(404, 'Dominio no encontrado para esta organización')
    return rows[0]['id']


# ---------------------------------------------------------------- dominios

DOMAINS_SQL = '''
SELECT d.id::text, d.fqdn::text, d.status, d.last_scan_at, d.next_scan_at,
       a.valid_from, a.valid_until, a.revoked_at, a.signer_email::text,
       (a.id IS NOT NULL AND a.revoked_at IS NULL AND current_date BETWEEN a.valid_from AND a.valid_until) AS auth_valid,
       t.result AS txt_result, t.checked_at AS txt_checked_at,
       s.score,
       (SELECT jsonb_object_agg(sev, n) FROM (SELECT severity AS sev, count(*) AS n FROM findings f
          WHERE f.domain_id = d.id AND f.status = 'open' GROUP BY severity) c) AS open_findings
  FROM domains d
  LEFT JOIN LATERAL (SELECT * FROM domain_authorizations x WHERE x.domain_id = d.id
                      ORDER BY (x.revoked_at IS NULL AND current_date BETWEEN x.valid_from AND x.valid_until) DESC,
                               x.valid_until DESC LIMIT 1) a ON true
  LEFT JOIN LATERAL (SELECT v.result, v.checked_at FROM dns_txt_verifications v
                      WHERE v.domain_id = d.id ORDER BY v.checked_at DESC LIMIT 1) t ON true
  LEFT JOIN LATERAL (SELECT ds.score FROM domain_scores ds
                      WHERE ds.domain_id = d.id ORDER BY ds.computed_at DESC LIMIT 1) s ON true
 WHERE d.status <> 'removed'
 ORDER BY s.score DESC NULLS LAST, d.status = 'pending_verification' DESC, d.fqdn
'''


def _domain(r):
    today = date.today()
    if r['valid_until'] is None:
        auth = 'missing'
    elif r['revoked_at']:
        auth = 'revoked'
    elif r['auth_valid']:
        auth = 'valid'
    elif r['valid_from'] > today:
        auth = 'missing'
    else:
        auth = 'expired'
    txt = 'verified' if r['txt_result'] == 'match' else 'missing'

    reasons = []
    if auth != 'valid':
        reasons.append({'missing': 'authorization_missing' if r['valid_from'] is None else 'authorization_not_started',
                        'revoked': 'authorization_revoked', 'expired': 'authorization_expired'}[auth])
    if r['status'] == 'paused':
        reasons.append('domain_paused')
    if r['status'] == 'pending_verification' or txt != 'verified':
        reasons.append('txt_not_verified')

    counts = {s: 0 for s in SEVERIDADES}
    counts.update(r['open_findings'] or {})
    return {
        'id': r['id'], 'fqdn': r['fqdn'], 'status': r['status'],
        'authorization': {'status': auth, 'valid_from': r['valid_from'], 'valid_until': r['valid_until'],
                          'signer_email': r['signer_email']},
        'txt': {'status': txt, 'checked_at': r['txt_checked_at']},
        'scan_eligibility': {'can_scan': not reasons, 'reasons': reasons},
        'score': r['score'], 'band': criterio.banda(r['score']) if r['score'] is not None else None,
        'open_findings': counts, 'last_scan_at': r['last_scan_at'], 'next_scan_at': r['next_scan_at'],
    }


@router.get('/domains/txt', summary='Registro TXT que cada dominio debe publicar (solo Admin)')
def txt_records(session: Session = Depends(require_roles('admin'))):
    rows = _query(session, '''
        SELECT d.fqdn::text, d.txt_token, t.result, t.checked_at
          FROM domains d
          LEFT JOIN LATERAL (SELECT v.result, v.checked_at FROM dns_txt_verifications v
                              WHERE v.domain_id = d.id ORDER BY v.checked_at DESC LIMIT 1) t ON true
         WHERE d.status <> 'removed' ORDER BY d.fqdn
    ''')
    items = [{'fqdn': r['fqdn'], 'status': 'verified' if r['result'] == 'match' else 'missing',
              'expected_value': txt_esperado(r['txt_token']), 'checked_at': r['checked_at']} for r in rows]
    return {'items': items, 'total': len(items)}


@router.get('/domains', summary='Dominios con autorización, TXT, si se pueden escanear, score y hallazgos abiertos')
def domains(session: Session = Depends(current_session)):
    items = [_domain(r) for r in _query(session, DOMAINS_SQL)]
    return {'items': items, 'total': len(items)}


# ---------------------------------------------------------------- hallazgos

FINDINGS_SQL = '''
SELECT f.id::text, f.evidence, a.value AS asset, a.asset_type, a.first_seen_at AS asset_first_seen,
       r.category, r.code AS rule_code, r.base_severity, s.code AS source, f.severity, f.status,
       f.cve_id, c.cvss_base_score AS cvss, c.epss_score AS epss, coalesce(c.in_kev, false) AS in_kev,
       f.detected_at, f.last_scan_id::text, sc.queued_at AS scan_at,
       b.breach_name, b.breach_date, b.data_classes,
       CASE WHEN sc.id IS NULL OR f.detected_at >= sc.queued_at THEN 'new' ELSE 'recurring' END AS recurrence
  FROM findings f
  JOIN domains d       ON d.id = f.domain_id
  JOIN assets a        ON a.id = f.asset_id
  JOIN scoring_rules r ON r.id = f.rule_id
  JOIN data_sources s  ON s.id = f.source_id
  LEFT JOIN scans sc   ON sc.id = f.last_scan_id
  LEFT JOIN cves c     ON c.cve_id = f.cve_id
  LEFT JOIN breach_exposures b ON b.finding_id = f.id
 WHERE d.fqdn = %s AND f.status = 'open'
 ORDER BY array_position(ARRAY['critical','high','medium','low'], f.severity), f.detected_at DESC, f.id
'''


def _finding(f):
    evidence = {k: v for k, v in f['evidence'].items() if k not in ('title', 'caracteristicas', 'huella')}
    if f['breach_name']:
        evidence.update(breach_name=f['breach_name'], breach_date=f['breach_date'], data_classes=f['data_classes'])
    return {
        'id': f['id'], 'title': f['evidence'].get('title', f['rule_code']), 'asset': f['asset'], 'asset_type': f['asset_type'],
        'category': f['category'], 'rule_code': f['rule_code'], 'source': f['source'], 'severity': f['severity'],
        'base_severity': f['base_severity'], 'status': f['status'], 'recurrence': f['recurrence'],
        'cve_id': f['cve_id'], 'cvss': float(f['cvss']) if f['cvss'] is not None else None,
        'epss': float(f['epss']) if f['epss'] is not None else None, 'in_kev': f['in_kev'],
        'evidence': evidence, 'caracteristicas': caracteristicas(f),
        'detected_at': f['detected_at'], 'last_scan_id': f['last_scan_id'],
    }


@router.get('/domains/{fqdn}/findings', summary='Hallazgos abiertos del dominio, de más a menos severo')
def domain_findings(fqdn: str, session: Session = Depends(current_session)):
    _domain_id(session, fqdn)
    items = [_finding(f) for f in _query(session, FINDINGS_SQL, (fqdn,))]
    return {'domain': fqdn, 'items': items, 'total': len(items)}


# ---------------------------------------------------------------- score e histórico

SCORES_SQL = '''
SELECT ds.id::text AS score_id, ds.score, ds.category_scores, ds.method, ds.reason, ds.partial_coverage,
       ds.computed_at, rs.version AS rule_set_version, rs.category_weights, sc.stats,
       (SELECT count(*) FROM score_contributions x WHERE x.score_id = ds.id AND x.severity = 'critical') AS critical_at_time
  FROM domain_scores ds
  JOIN domains d ON d.id = ds.domain_id
  JOIN scoring_rule_sets rs ON rs.id = ds.rule_set_id
  LEFT JOIN scans sc ON sc.id = ds.scan_id
 WHERE d.fqdn = %s
 ORDER BY ds.computed_at
'''


def _score_base(row, critical_open):
    weights = {k: float(v) for k, v in row['category_weights'].items()}
    calc = criterio.score_dominio(row['category_scores'], weights, critical_open)
    return {
        'score_id': row['score_id'], 'score': row['score'], 'band': criterio.banda(row['score']),
        'weighted': calc['ponderado'], 'floor': calc['piso'], 'floor_applied': row['score'] > calc['ponderado'],
        'critical_open': critical_open, 'method': row['method'], 'rule_set_version': row['rule_set_version'],
        'reason': row['reason'], 'partial_coverage': row['partial_coverage'], 'computed_at': row['computed_at'],
        'floor_message': motor.mensaje_piso(calc, critical_open),
    }, weights


@router.get('/domains/{fqdn}/score', summary='Score más reciente con su desglose por categoría')
def domain_score(fqdn: str, session: Session = Depends(current_session)):
    domain_id = _domain_id(session, fqdn)
    rows = _query(session, SCORES_SQL, (fqdn,))
    if not rows:
        raise HTTPException(404, 'El dominio aún no tiene score')
    with transaction(session.org_id) as conn:
        critical_open = conn.execute(
            "SELECT count(*) AS n FROM findings WHERE domain_id = %s AND severity = 'critical' AND status = ANY(%s)",
            (domain_id, list(criterio.ESTADOS_VIGENTES))).fetchone()['n']
        threshold = conn.execute('SELECT alert_score_threshold AS t FROM organizations').fetchone()['t']
    base, weights = _score_base(rows[-1], critical_open)
    categories = [{'category': c, 'score': rows[-1]['category_scores'][c], 'band': criterio.banda(rows[-1]['category_scores'][c]),
                   'weight': weights[c]} for c in criterio.CATEGORIAS]
    return {'domain': fqdn, **base, 'categories': categories,
            'alert': {'threshold': threshold, 'triggered': criterio.dispara_alerta(base['score'], threshold)}}


@router.get('/domains/{fqdn}/score/history', summary='Todos los scores del dominio, del más viejo al más nuevo')
def score_history(fqdn: str, session: Session = Depends(current_session)):
    _domain_id(session, fqdn)
    items = []
    for row in _query(session, SCORES_SQL, (fqdn,)):
        base, _ = _score_base(row, row['critical_at_time'])
        stats = row['stats'] or {}
        items.append({**base, 'categories': row['category_scores'],
                      'new_findings': stats.get('new_findings', 0), 'resolved_findings': stats.get('resolved_findings', 0)})
    return {'domain': fqdn, 'items': items, 'total': len(items)}


# ---------------------------------------------------------------- explicación

EXPLANATION_SQL = '''
SELECT f.id::text AS finding_id, d.fqdn::text AS domain, f.evidence, f.severity, r.base_severity, r.category,
       r.code AS rule_code, r.max_penalty, a.value AS asset, a.asset_type, a.first_seen_at AS asset_first_seen,
       f.detected_at, sc.queued_at AS scan_at, b.breach_date,
       ds.id::text AS score_id, ds.computed_at, ds.method, x.penalty, x.factors,
       t.title AS rule_title, t.meaning, t.recommendation
  FROM findings f
  JOIN domains d ON d.id = f.domain_id
  JOIN assets a ON a.id = f.asset_id
  JOIN scoring_rules r ON r.id = f.rule_id
  JOIN scoring_rule_texts t ON t.code = r.code
  LEFT JOIN scans sc ON sc.id = f.last_scan_id
  LEFT JOIN breach_exposures b ON b.finding_id = f.id
  LEFT JOIN LATERAL (SELECT * FROM domain_scores s WHERE s.domain_id = f.domain_id ORDER BY s.computed_at DESC LIMIT 1) ds ON true
  LEFT JOIN score_contributions x ON x.score_id = ds.id AND x.finding_id = f.id
 WHERE f.id = %s
'''


@router.get('/findings/{finding_id}/explanation', summary='Por qué el hallazgo tiene su severidad y cuánto suma al score')
def finding_explanation(finding_id: str, session: Session = Depends(current_session)):
    try:
        finding_id = str(uuid.UUID(finding_id))
    except ValueError:
        raise HTTPException(404, 'Hallazgo no encontrado')  # un id mal formado se responde igual que uno de otra empresa
    # Sin try: un error de la base (por ejemplo, sin la migración 003) llega al log y responde 500, no 404.
    rows = _query(session, EXPLANATION_SQL, (finding_id,))
    if not rows:
        raise HTTPException(404, 'Hallazgo no encontrado')
    f = rows[0]
    factors = [{'label': FACTOR_ES.get(r['label'], r['label']), 'points': r['points']}
               for r in ((f['factors'] or {}).get('rules') or [])]
    return {
        'finding_id': f['finding_id'], 'domain': f['domain'], 'title': f['evidence'].get('title', f['rule_code']),
        'severity': f['severity'], 'base_severity': f['base_severity'], 'category': f['category'], 'rule_code': f['rule_code'],
        'rule_title': f['rule_title'], 'meaning': f['meaning'],
        'score_id': f['score_id'], 'computed_at': f['computed_at'], 'method': f['method'] or 'rules',
        'penalty': float(f['penalty']) if f['penalty'] is not None else 0.0, 'max_penalty': float(f['max_penalty']),
        'factors': factors, 'caracteristicas': caracteristicas(f),
        'summary': RESUMEN[f['severity']],
        'recommendation': f['recommendation'],
        'confidence': None, 'shap': None,
    }


# ---------------------------------------------------------------- pesos, activos y escaneos

@router.get('/scoring/weights', summary='Juego de reglas activo: pesos, bandas, piso, umbral y reglas')
def scoring_weights(session: Session = Depends(current_session)):
    with transaction(session.org_id) as conn:
        rs = conn.execute('SELECT id, version, category_weights, activated_at, validated_by FROM scoring_rule_sets WHERE is_active').fetchone()
        rules = conn.execute('SELECT r.code, r.category, r.base_severity, r.weight, r.max_penalty, '
                             't.title, t.meaning, t.recommendation FROM scoring_rules r '
                             'JOIN scoring_rule_texts t ON t.code = r.code '
                             'WHERE r.rule_set_id = %s ORDER BY r.id', (rs['id'],)).fetchall()
    return {
        'rule_set_version': rs['version'], 'is_active': True, 'activated_at': rs['activated_at'],
        'validated_by': rs['validated_by'], 'category_weights': {k: float(v) for k, v in rs['category_weights'].items()},
        'bands': [{'band': c, 'from': d, 'to': h} for d, h, c, _ in criterio.BANDAS],
        'floor': {'one_critical': criterio.PISO_UN_CRITICO, 'two_or_more_critical': criterio.PISO_VARIOS_CRITICOS,
                  'counts_statuses': list(criterio.ESTADOS_VIGENTES)},
        'alert_threshold_default': criterio.UMBRAL_ALERTA,
        'rules': [{**r, 'weight': float(r['weight']), 'max_penalty': float(r['max_penalty'])} for r in rules],
    }


@router.get('/domains/{fqdn}/assets', summary='Activos del dominio (provisional, aún no está en el contrato #21)')
def domain_assets(fqdn: str, session: Session = Depends(current_session)):
    _domain_id(session, fqdn)
    rows = _query(session, '''
        SELECT a.id::text, a.asset_type AS type, a.value, p.value AS parent, a.attributes, a.first_seen_at, a.last_seen_at
          FROM assets a JOIN domains d ON d.id = a.domain_id LEFT JOIN assets p ON p.id = a.parent_asset_id
         WHERE d.fqdn = %s ORDER BY array_position(ARRAY['domain','subdomain','certificate','ip','service','email'], a.asset_type), a.value
    ''', (fqdn,))
    return {'items': rows, 'total': len(rows)}


@router.get('/scans', summary='Escaneos de la organización, del más nuevo al más viejo (provisional)')
def scans(session: Session = Depends(current_session)):
    with transaction(session.org_id) as conn:
        orquestador.abandonar_vencidos(conn, session.org_id)  # uno caído no se muestra en curso
    rows = _query(session, '''
        SELECT s.id::text, d.fqdn::text AS domain, s.trigger_type AS trigger, s.status, s.queued_at, s.finished_at, s.stats,
               coalesce((SELECT jsonb_agg(jsonb_build_object('source', ds.code, 'status', r.status, 'attempt', r.attempt,
                                                             'error', r.error, 'finished_at', r.finished_at) ORDER BY ds.code)
                           FROM scan_source_runs r JOIN data_sources ds ON ds.id = r.source_id WHERE r.scan_id = s.id), '[]') AS sources
          FROM scans s JOIN domains d ON d.id = s.domain_id
         ORDER BY s.queued_at DESC LIMIT 50
    ''')
    return {'items': rows, 'total': len(rows)}

"""Cirdan · API REST inicial (FastAPI) sobre la base `cirdan`.

Entra como el rol de la aplicación `cirdan_app` (sin superusuario ni BYPASSRLS).
Cada petición abre una transacción y fija `app.current_org` con el cliente que
envía el encabezado `X-Organization`; Row-Level Security hace el resto, así que
ninguna consulta filtra por organización.

Modo demo: el cliente se identifica con el id de su organización. En producción
será la llave de API de la tabla `api_keys` (hash, alcance y vigencia).

    python -m uvicorn cirdan.api.main:app --port 8000      (desde la raíz del repo)
    Documentación: http://127.0.0.1:8000/docs
"""
import os
import uuid

import psycopg
from fastapi import FastAPI, Header, HTTPException
from psycopg.rows import dict_row

from cirdan import RAIZ

ENV = dict(line.split('=', 1) for line in (RAIZ / '.env').read_text().split()
           if '=' in line)
DSN = 'host=127.0.0.1 port=%s dbname=cirdan user=cirdan_app password=%s' % (
    os.environ.get('PGPORT', ENV.get('PGPORT', '5433')), ENV['CIRDAN_APP_PASSWORD'])

app = FastAPI(
    title='Cirdan API',
    version='0.1.0',
    description='Primeros endpoints de solo lectura sobre la base cirdan (PostgreSQL 16). '
                'El aislamiento entre clientes lo aplica Row-Level Security en la base. '
                'Vista visual de la base en /demo.',
)

from cirdan.api.explorer import register  # noqa: E402  (needs DSN, defined above)
register(app, DSN)


def query(org, sql, params=()):
    try:
        org = str(uuid.UUID(org))
    except (TypeError, ValueError):
        raise HTTPException(400, 'X-Organization debe ser el id (uuid) de la organización')
    if any(chr(0) in str(p) for p in params):
        raise HTTPException(400, 'Parámetro inválido')
    with psycopg.connect(DSN, row_factory=dict_row) as conn:
        with conn.transaction():
            conn.execute("SET LOCAL TIME ZONE 'America/Mexico_City'")
            conn.execute("SELECT set_config('app.current_org', %s, true)", (org,))
            return conn.execute(sql, params).fetchall()


LEVEL = """CASE WHEN {s} IS NULL THEN NULL WHEN {s} >= 80 THEN 'Critical' WHEN {s} >= 60 THEN 'High'
                WHEN {s} >= 40 THEN 'Medium' ELSE 'Low' END"""

DOMAINS = """
SELECT d.fqdn AS domain,
       CASE WHEN d.status = 'pending_verification' THEN 'Pending TXT'
            WHEN a.id IS NULL                      THEN 'Not authorized'
            WHEN a.revoked_at IS NOT NULL          THEN 'Revoked'
            WHEN current_date > a.valid_until      THEN 'Expired'
            ELSE 'Authorized' END                                   AS authorization,
       CASE WHEN t.result = 'match'                THEN 'Verified'
            WHEN d.status = 'pending_verification' THEN 'Pending'
            ELSE 'Not found' END                                    AS txt,
       a.valid_until::text                                          AS valid_until,
       s.score                                                      AS score,
       """ + LEVEL.format(s='s.score') + """                        AS level,
       d.last_scan_at                                               AS last_scan
  FROM domains d
  LEFT JOIN LATERAL (SELECT * FROM domain_authorizations x
                      WHERE x.domain_id = d.id ORDER BY x.valid_until DESC LIMIT 1) a ON true
  LEFT JOIN LATERAL (SELECT v.result FROM dns_txt_verifications v
                      WHERE v.domain_id = d.id ORDER BY v.checked_at DESC LIMIT 1) t ON true
  LEFT JOIN LATERAL (SELECT ds.score FROM domain_scores ds
                      WHERE ds.domain_id = d.id ORDER BY ds.computed_at DESC LIMIT 1) s ON true
 ORDER BY s.score DESC NULLS LAST, d.status = 'pending_verification' DESC, d.fqdn
"""

FINDINGS = """
SELECT f.evidence->>'title'                                 AS finding,
       a.value                                              AS asset,
       initcap(replace(r.category, '_', ' '))               AS category,
       CASE s.code WHEN 'hibp' THEN 'HIBP API' WHEN 'shodan' THEN 'Shodan' WHEN 'dns' THEN 'DNS'
                   WHEN 'ct_logs' THEN 'CT' WHEN 'whois' THEN 'WHOIS' ELSE s.code END AS source,
       initcap(f.severity)                                  AS severity,
       CASE WHEN f.status <> 'open'            THEN initcap(f.status)
            WHEN sc.id IS NULL                 THEN 'New'
            WHEN f.detected_at >= sc.queued_at THEN 'New'
            ELSE 'Recurring' END                            AS status
  FROM findings f
  JOIN domains d       ON d.id = f.domain_id
  JOIN assets a        ON a.id = f.asset_id
  JOIN scoring_rules r ON r.id = f.rule_id
  JOIN data_sources s  ON s.id = f.source_id
  LEFT JOIN scans sc   ON sc.id = f.last_scan_id
 WHERE d.fqdn = %s AND f.status = 'open'
 ORDER BY array_position(ARRAY['critical','high','medium','low'], f.severity), f.detected_at DESC, f.id
"""

SCORE = """
SELECT ds.score, """ + LEVEL.format(s='ds.score') + """ AS level, rs.version AS rule_set,
       ds.category_scores, rs.category_weights, ds.computed_at
  FROM domain_scores ds
  JOIN domains d            ON d.id = ds.domain_id
  JOIN scoring_rule_sets rs ON rs.id = ds.rule_set_id
 WHERE d.fqdn = %s
 ORDER BY ds.computed_at DESC LIMIT 1
"""

CATEGORIES = [('infrastructure', 'Infrastructure'), ('digital_identity', 'Digital Identity'),
              ('configuration', 'Configuration'), ('data_leaks', 'Data Leaks')]


def known_domain(org, fqdn):
    if not query(org, 'SELECT 1 FROM domains WHERE fqdn = %s', (fqdn,)):
        # RLS hides other clients' domains, so they look exactly like domains that do not exist
        raise HTTPException(404, 'Dominio no encontrado para esta organización')


@app.get('/health', tags=['sistema'], summary='Estado de la API y de la base')
def health():
    with psycopg.connect(DSN) as conn:
        version = conn.execute('SHOW server_version').fetchone()[0]
        role = conn.execute('SELECT current_user').fetchone()[0]
    return {'status': 'ok', 'postgres': version, 'role': role}


@app.get('/domains', tags=['dominios'], summary='Dominios del cliente con autorización, TXT y score')
def list_domains(x_organization: str = Header(..., description='Id (uuid) de la organización')):
    return query(x_organization, DOMAINS)


@app.get('/domains/{fqdn}/findings', tags=['dominios'], summary='Hallazgos abiertos de un dominio, por severidad')
def list_findings(fqdn: str, x_organization: str = Header(..., description='Id (uuid) de la organización')):
    known_domain(x_organization, fqdn)
    return query(x_organization, FINDINGS, (fqdn,))


@app.get('/domains/{fqdn}/score', tags=['dominios'], summary='Score de exposición por categoría con sus pesos')
def domain_score(fqdn: str, x_organization: str = Header(..., description='Id (uuid) de la organización')):
    known_domain(x_organization, fqdn)
    rows = query(x_organization, SCORE, (fqdn,))
    if not rows:
        raise HTTPException(404, 'El dominio aún no tiene score')
    r = rows[0]
    return {
        'domain': fqdn, 'score': r['score'], 'level': r['level'], 'rule_set': r['rule_set'],
        'computed_at': r['computed_at'],
        'categories': [{'category': label, 'score': r['category_scores'][key],
                        'weight': float(r['category_weights'][key])} for key, label in CATEGORIES],
    }

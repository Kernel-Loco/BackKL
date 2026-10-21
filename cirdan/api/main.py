"""Cirdan · API REST (FastAPI) sobre la base `cirdan`.

Entra como el rol de la aplicación `cirdan_app` (sin superusuario ni BYPASSRLS). La empresa
de quien llama sale de su sesión (cookie httpOnly `lt_session`, #25): cada petición fija
`app.current_org` con ella y Row-Level Security hace el resto, así que ninguna consulta
filtra por organización. Ninguna ruta toma la empresa de un encabezado. El explorador de /demo
y /db solo existe con DEMO_EXPLORER=true y también pide sesión (RC-58).

    docker compose up -d            (o, fuera de Docker: python -m uvicorn cirdan.api.main:app --port 8000)
    Documentación: http://127.0.0.1:8000/docs
"""
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from cirdan.auth.deps import Session, current_session
from cirdan.api.escaneos import router as scans_router
from cirdan.api.explorer import router as explorer_router
from cirdan.api.v1 import router as v1_router
from cirdan.auth.routes import router as auth_router
from cirdan.config import config
from cirdan.db import transaction

app = FastAPI(
    title='Cirdan API',
    version='0.2.0',
    description='Inicio de sesión con MFA y endpoints de solo lectura sobre la base cirdan (PostgreSQL 16). '
                'La empresa sale de la sesión y el aislamiento lo aplica Row-Level Security en la base. '
                'Con DEMO_EXPLORER=true, vista visual de la base en /demo, también con sesión.',
)

# Orígenes que pueden mandar POST con la cookie: el portal y la propia API.
ALLOWED_ORIGINS = {o.strip() for o in config(
    'ALLOWED_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000').split(',')}


@app.middleware('http')
async def same_origin_writes(request: Request, call_next):
    """Contra CSRF: además de SameSite=Lax, una escritura con Origin ajeno se rechaza."""
    origin = request.headers.get('origin')
    if request.method not in ('GET', 'HEAD', 'OPTIONS') and origin:
        parts = urlsplit(origin)
        if '%s://%s' % (parts.scheme, parts.netloc) not in ALLOWED_ORIGINS:
            return JSONResponse({'detail': 'Origen no permitido'}, status_code=403)
    return await call_next(request)


app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(v1_router)

# Explorador de la base para la demo (/demo y /db, RC-58). Con false, que es lo de omisión, esas
# rutas no existen (404). Nunca true en producción.
if config('DEMO_EXPLORER', 'false').lower() == 'true':
    app.include_router(explorer_router)


def query(session, sql, params=()):
    if any(chr(0) in str(p) for p in params):
        raise HTTPException(400, 'Parámetro inválido')
    with transaction(session.org_id) as conn:
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


def known_domain(session, fqdn):
    if not query(session, 'SELECT 1 FROM domains WHERE fqdn = %s', (fqdn,)):
        # RLS hides other clients' domains, so they look exactly like domains that do not exist
        raise HTTPException(404, 'Dominio no encontrado para esta organización')


@app.get('/health', tags=['sistema'], summary='Estado de la API y de la base')
def health():
    with transaction() as conn:
        row = conn.execute("SELECT current_setting('server_version') AS version, current_user AS role").fetchone()
    return {'status': 'ok', 'postgres': row['version'], 'role': row['role']}


@app.get('/domains', tags=['dominios'], summary='Dominios del cliente con autorización, TXT y score')
def list_domains(session: Session = Depends(current_session)):
    return query(session, DOMAINS)


@app.get('/domains/{fqdn}/findings', tags=['dominios'], summary='Hallazgos abiertos de un dominio, por severidad')
def list_findings(fqdn: str, session: Session = Depends(current_session)):
    known_domain(session, fqdn)
    return query(session, FINDINGS, (fqdn,))


@app.get('/domains/{fqdn}/score', tags=['dominios'], summary='Score de exposición por categoría con sus pesos')
def domain_score(fqdn: str, session: Session = Depends(current_session)):
    known_domain(session, fqdn)
    rows = query(session, SCORE, (fqdn,))
    if not rows:
        raise HTTPException(404, 'El dominio aún no tiene score')
    r = rows[0]
    return {
        'domain': fqdn, 'score': r['score'], 'level': r['level'], 'rule_set': r['rule_set'],
        'computed_at': r['computed_at'],
        'categories': [{'category': label, 'score': r['category_scores'][key],
                        'weight': float(r['category_weights'][key])} for key, label in CATEGORIES],
    }

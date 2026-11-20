"""API v1 de lectura para el portal (RC-17), con la forma del contrato de docs/contrato_api_v1.md (#21).

Todo con sesión: la empresa sale de la cookie y RLS filtra en la base. Las bandas, el ponderado y
el piso salen del criterio de criticidad (cirdan/score/criterio.py, #29), con los cortes del juego de reglas con que
se calculó cada score (RC-237), nunca con los de la plantilla.

Los GET de datos también aceptan una llave de API (#87, RC-129) con session_or_api_key, salvo la salida
a SIEM (export/siem), que por ahora pide la sesión. La empresa sale de la llave y RLS filtra igual.
Una llave de un solo dominio además pasa por in_scope(): toda ruta nueva que acepte llave y lea datos
de un dominio tiene que revisarlo, porque RLS aísla por empresa, no por dominio.
"""
import base64
import binascii
import json
import re
import secrets
import uuid
from datetime import date, datetime

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from psycopg import IsolationLevel
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from cirdan import cartas, orquestador, reporte, siem
from cirdan.api.llaves import SIN_SESION
from cirdan.auth import sessions
from cirdan.auth.deps import (Session, api_key_or_roles, client_ip, current_session, in_scope, require_roles,
                              session_or_api_key)
from cirdan.exportar import csv_con_bom
from cirdan.orquestador.txt import esperado as txt_esperado
from cirdan.orquestador import txt as dns_txt
from cirdan.db import audit, transaction
from cirdan.score import cambios, cobertura, comparacion, configuracion, criterio, motor, plan as plan_accion, subcategorias

router = APIRouter(prefix='/api/v1', tags=['portal'])
SEVERIDADES = ('critical', 'high', 'medium', 'low')
# Lista, CSV, explicación y comparación de hallazgos: como en el portal (src/config/permissions.ts), el gerente no los ve y se
# queda con los conteos por severidad de GET /domains (RC-280). Una llave de API entra igual.
LEE_HALLAZGOS = api_key_or_roles('analyst', 'admin')

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


# Sin respaldo: la FK diferida de la migración 012 obliga a que todo texto de regla tenga su mapeo
# (scoring_rule_framework_mappings, 011). Si falta, la base no tiene la 012 (entró un texto sin mapeo o se borró un
# mapeo) y responden 500 toda la lista de hallazgos del dominio y la explicación del hallazgo.
def _marcos(f):
    if not f['attack_version']:
        raise RuntimeError('Falta el mapeo de marcos para la regla %s' % f['rule_code'])
    return {
        'mitre_attack': {
            'version': f['attack_version'],
            'technique_id': f['attack_technique_id'],
            'technique_name': f['attack_technique_name'],
            'source_url': f['attack_source_url'],
            'unmapped_reason': f['attack_unmapped_reason'],
        },
        'iso_27001_2022': {
            'version': f['iso_version'],
            'control_id': f['iso_control_id'],
            'control_name': f['iso_control_name'],
            'source_url': f['iso_source_url'],
        },
        'cis_controls_v8_1': {
            'version': f['cis_version'],
            'safeguard_id': f['cis_safeguard_id'],
            'safeguard_name': f['cis_safeguard_name'],
            'source_url': f['cis_source_url'],
        },
    }


def _domain_id(session, fqdn):
    rows = _query(session, 'SELECT id::text FROM domains WHERE fqdn = %s', (fqdn,))
    if not rows or not in_scope(session, rows[0]['id']):  # fuera del alcance de la llave se ve igual que ajeno
        raise HTTPException(404, 'Dominio no encontrado para esta organización')
    return rows[0]['id']


# ---------------------------------------------------------------- dominios

# El correo de quien firma sale solo con la carta vigente. Revocada, vencida o sin empezar, sus datos están en bloqueo
# (sección 5.6 de docs/politica_seguridad_privacidad.md) y la base da NULL, con su fecha de México (RC-274).
DOMAINS_SQL = '''
SELECT d.id::text, d.fqdn::text, d.status, d.last_scan_at, d.next_scan_at,
       a.valid_from, a.valid_until, a.revoked_at,
       CASE WHEN a.revoked_at IS NULL AND current_date BETWEEN a.valid_from AND a.valid_until
            THEN a.signer_email::text END AS signer_email,
       (a.id IS NOT NULL AND a.revoked_at IS NULL AND current_date BETWEEN a.valid_from AND a.valid_until) AS auth_valid,
       (a.valid_from > current_date) AS auth_not_started,
       t.result AS txt_result, t.checked_at AS txt_checked_at,
       s.score, s.band_medium_from, s.band_high_from, s.band_critical_from,
       (SELECT jsonb_object_agg(sev, n) FROM (SELECT coalesce(sc_score.severity, f.severity) AS sev, count(*) AS n
          FROM findings f
          LEFT JOIN LATERAL (SELECT x.severity FROM score_contributions x
                              WHERE x.finding_id = f.id
                                AND x.score_id = (SELECT ds.id FROM domain_scores ds WHERE ds.domain_id = f.domain_id
                                                   ORDER BY ds.computed_at DESC LIMIT 1)) sc_score ON true
          WHERE f.domain_id = d.id AND f.status = 'open' GROUP BY 1) c) AS open_findings
  FROM domains d
  LEFT JOIN LATERAL (SELECT * FROM domain_authorizations x WHERE x.domain_id = d.id
                      ORDER BY (x.revoked_at IS NULL AND current_date BETWEEN x.valid_from AND x.valid_until) DESC,
                               x.valid_until DESC LIMIT 1) a ON true
  LEFT JOIN LATERAL (SELECT v.result, v.checked_at FROM dns_txt_verifications v
                      WHERE v.domain_id = d.id ORDER BY v.checked_at DESC LIMIT 1) t ON true
  LEFT JOIN LATERAL (SELECT ds.score, rs.band_medium_from, rs.band_high_from, rs.band_critical_from FROM domain_scores ds
                      JOIN scoring_rule_sets rs ON rs.id = ds.rule_set_id
                      WHERE ds.domain_id = d.id ORDER BY ds.computed_at DESC LIMIT 1) s ON true
 WHERE d.status <> 'removed'
 ORDER BY s.score DESC NULLS LAST, d.status = 'pending_verification' DESC, d.fqdn
'''


def _domain(r):
    # La base decide si la carta ya empezó o venció, con su current_date en la zona de México (cirdan/db.py). El
    # contenedor de la API va en UTC: con date.today(), de 18:00 a 24:00 una carta que empieza mañana salía 'expired'
    # (RC-313).
    if r['valid_until'] is None:
        auth = 'missing'
    elif r['revoked_at']:
        auth = 'revoked'
    elif r['auth_valid']:
        auth = 'valid'
    elif r['auth_not_started']:
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
    cortes = configuracion.cortes_de_fila(r) if r['score'] is not None else None
    return {
        'id': r['id'], 'fqdn': r['fqdn'], 'status': r['status'],
        'authorization': {'status': auth, 'valid_from': r['valid_from'], 'valid_until': r['valid_until'],
                          'signer_email': r['signer_email']},
        'txt': {'status': txt, 'checked_at': r['txt_checked_at']},
        'scan_eligibility': {'can_scan': not reasons, 'reasons': reasons},
        'score': r['score'], 'band': criterio.banda(r['score'], cortes) if r['score'] is not None else None,
        'grade': criterio.letra(r['score'], cortes) if r['score'] is not None else None,
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


MAX_CARTA = 5 * 1024 * 1024
MAX_ALTA_BODY = (MAX_CARTA + 2) // 3 * 4 + 16384
FQDN_ALTA = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
EMAIL_ALTA = re.compile(r'[^\s@]+@[^\s@]+\.[^\s@]+')


def _datos_alta(body):
    campos = ('fqdn', 'signer_name', 'signer_title', 'signer_email', 'valid_from', 'valid_until', 'letter_base64')
    if not isinstance(body, dict) or set(body) != set(campos) | {'passive_monitoring_confirmed'}:
        raise HTTPException(422, 'Revisa los datos del dominio y de la carta.')
    if any(not isinstance(body[c], str) for c in campos) or body['passive_monitoring_confirmed'] is not True:
        raise HTTPException(422, 'Revisa los datos y confirma la autorización.')
    fqdn = body['fqdn'].strip().lower().removesuffix('.')
    name, title, email = (body[c].strip() for c in ('signer_name', 'signer_title', 'signer_email'))
    if not FQDN_ALTA.fullmatch(fqdn):
        raise HTTPException(422, 'Escribe un dominio válido, como ejemplo.com.')
    if not name or not title or len(name) > 200 or len(title) > 200 or len(email) > 254 or not EMAIL_ALTA.fullmatch(email):
        raise HTTPException(422, 'Escribe el nombre, cargo y correo de quien firma.')
    if any('\x00' in text for text in (name, title, email)):
        raise HTTPException(422, 'Los datos no pueden contener caracteres nulos.')
    try:
        start = date.fromisoformat(body['valid_from'])
        end = date.fromisoformat(body['valid_until'])
    except ValueError:
        raise HTTPException(422, 'Escribe fechas válidas para la carta.') from None
    if end <= start:
        raise HTTPException(422, 'La fecha de fin debe ser posterior al inicio.')
    try:
        pdf = base64.b64decode(body['letter_base64'], validate=True)
    except (ValueError, binascii.Error):
        raise HTTPException(422, 'No se pudo leer el PDF.') from None
    if len(pdf) > MAX_CARTA:
        raise HTTPException(413, 'El PDF no puede superar 5 MB.')
    if not pdf.startswith(b'%PDF-') or b'%%EOF' not in pdf[-1024:]:
        raise HTTPException(422, 'La carta debe ser un PDF válido.')
    return fqdn, name, title, email, start, end, pdf


def _registrar_dominio(body, request, session):
    if session.acting_elsewhere:
        raise HTTPException(403, 'El alta debe hacerla un administrador de la propia empresa.')
    fqdn, name, title, email, start, end, pdf = _datos_alta(body)
    token = secrets.token_hex(16)
    try:
        with transaction(session.org_id) as conn:
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s, 44))', (session.org_id,))
            organization = conn.execute(
                'SELECT o.status, coalesce(o.domain_limit_override, p.max_domains) AS limit '
                'FROM organizations o JOIN plans p ON p.id = o.plan_id WHERE o.id = %s',
                (session.org_id,),
            ).fetchone()
            if not organization or organization['status'] not in ('trial', 'active'):
                raise HTTPException(403, 'La organización no está activa.')
            count = conn.execute("SELECT count(*) AS total FROM domains WHERE status <> 'removed'").fetchone()['total']
            if count >= organization['limit']:
                raise HTTPException(409, 'La organización alcanzó su límite de dominios.')
            domain_id = conn.execute(
                "INSERT INTO domains (organization_id, fqdn, status, txt_token, added_by) "
                "VALUES (%s, %s, 'pending_verification', %s, %s) RETURNING id::text",
                (session.org_id, fqdn, token, session.user_id),
            ).fetchone()['id']
            key, digest = cartas.guardar(pdf, session.org_id, domain_id)
            conn.execute(
                'INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, '
                'signer_email, signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                (session.org_id, domain_id, name, title, email, key, digest, start, end, session.user_id),
            )
            audit(conn, session.org_id, 'domain.added', session.audit_user_id, client_ip(request), 'domain',
                  domain_id, {'fqdn': fqdn}, platform=session.audit_platform)
            domain = next(_domain(row) for row in conn.execute(DOMAINS_SQL).fetchall() if row['id'] == domain_id)
    except UniqueViolation as error:
        if error.diag.constraint_name == 'domains_organization_id_fqdn_key':
            raise HTTPException(409, 'Ese dominio ya está registrado en esta organización.') from None
        raise
    return {'domain': domain, 'txt': {'fqdn': fqdn, 'status': 'missing',
                                       'expected_value': dns_txt.esperado(token), 'checked_at': None}}


@router.post('/domains', status_code=201, summary='Registra un dominio y su carta (solo Admin)')
async def register_domain(request: Request, session: Session = Depends(require_roles('admin'))):
    if not cartas.habilitado():
        raise HTTPException(409, 'El alta de dominios no está habilitada: falta configurar el almacenamiento y su respaldo.')
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > MAX_ALTA_BODY:
            raise HTTPException(413, 'El PDF no puede superar 5 MB.')
        raw.extend(chunk)
    try:
        body = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(422, 'El cuerpo de la solicitud no es válido.') from None
    return await run_in_threadpool(_registrar_dominio, body, request, session)


@router.post('/domains/{fqdn}/txt/verify', summary='Verifica el TXT del dominio (solo Admin)')
def verify_domain_txt(fqdn: str, request: Request, session: Session = Depends(require_roles('admin'))):
    with transaction(session.org_id) as conn:
        domain = conn.execute(
            "SELECT id::text, fqdn::text, status, txt_token FROM domains "
            "WHERE fqdn = %s AND status <> 'removed' FOR UPDATE", (fqdn.strip().lower().rstrip('.'),)
        ).fetchone()
        if not domain:
            raise HTTPException(404, 'Dominio no encontrado para esta organización')
        motivos, _ = orquestador._motivos_previos(conn, domain)
        if motivos:
            raise HTTPException(409, orquestador._texto(motivos).replace('No se puede escanear:', 'No se puede verificar el TXT:', 1))
        if not orquestador.en_vivo_permitido(domain['fqdn']):
            raise HTTPException(403, 'Este dominio no está habilitado para consultas DNS en vivo.')

        consulta = dns_txt.consultar_dns(domain['fqdn'])
        resultado = dns_txt.resultado(consulta, domain['txt_token'])
        esperado = dns_txt.esperado(domain['txt_token'])
        checked_at = conn.execute(
            'INSERT INTO dns_txt_verifications (organization_id, domain_id, check_reason, expected_value, '
            'observed_values, resolver_ip, result, checked_at) VALUES (%s, %s, %s, %s, %s, %s, %s, clock_timestamp()) '
            'RETURNING checked_at',
            (session.org_id, domain['id'], 'onboarding', esperado,
             [esperado] if resultado == 'match' else None, consulta.resolver_ip, resultado),
        ).fetchone()['checked_at']
        if resultado == 'match' and domain['status'] == 'pending_verification':
            try:
                with conn.transaction():
                    conn.execute(
                        "UPDATE domains SET status = 'verified', verified_at = coalesce(verified_at, now()), "
                        "updated_at = now() WHERE id = %s", (domain['id'],)
                    )
            except UniqueViolation:
                raise HTTPException(409, 'El dominio ya está verificado por otra organización.')
        audit(conn, session.org_id, 'domain.txt_checked', session.audit_user_id, client_ip(request), 'domain',
              domain['id'], {'result': resultado}, platform=session.audit_platform)
        rows = conn.execute(DOMAINS_SQL).fetchall()
        updated = next(_domain(row) for row in rows if row['id'] == domain['id'])

    if resultado == 'dns_error':
        raise HTTPException(503, 'No se pudo consultar el DNS. Inténtalo de nuevo más tarde.')
    return {
        'domain': updated,
        'txt': {'fqdn': domain['fqdn'], 'status': 'verified' if resultado == 'match' else 'missing',
                'expected_value': esperado, 'checked_at': checked_at},
    }


@router.get('/domains', summary='Dominios con autorización, TXT, si se pueden escanear, score y hallazgos abiertos')
def domains(session: Session = Depends(session_or_api_key)):
    items = [_domain(r) for r in _query(session, DOMAINS_SQL) if in_scope(session, r['id'])]
    return {'items': items, 'total': len(items)}


# ---------------------------------------------------------------- hallazgos

FINDINGS_SQL = '''
SELECT f.id::text, f.evidence, a.value AS asset, a.asset_type, a.first_seen_at AS asset_first_seen,
    r.category, r.code AS rule_code, r.base_severity, s.code AS source,
    coalesce(sc_score.severity, f.severity) AS severity, f.status,
       f.cve_id, coalesce(c.cvss_base_score, CASE WHEN jsonb_typeof(f.evidence->'cvss') = 'number' THEN
           CASE WHEN (f.evidence->>'cvss')::numeric BETWEEN 0 AND 10 THEN (f.evidence->>'cvss')::numeric END END)
           AS cvss,
       c.epss_score AS epss,
       -- Sin CVE, false. Con CVE, KEV solo se sabe si el cargador diario de inteligencia (#69, RC-127) ya pasó por
       -- la fila (intel_updated_at). Un stub del orquestador trae in_kev = false por omisión, y eso no es un «no».
       CASE WHEN f.cve_id IS NULL THEN false WHEN c.intel_updated_at IS NULL THEN NULL ELSE c.in_kev END AS in_kev,
       f.detected_at, f.last_scan_id::text, sc.queued_at AS scan_at,
       b.breach_name, b.breach_date, b.data_classes,
       fm.attack_version, fm.attack_technique_id, fm.attack_technique_name,
       fm.attack_source_url, fm.attack_unmapped_reason,
       fm.iso_version, fm.iso_control_id, fm.iso_control_name, fm.iso_source_url,
       fm.cis_version, fm.cis_safeguard_id, fm.cis_safeguard_name, fm.cis_source_url,
       CASE WHEN sc.id IS NULL OR f.detected_at >= sc.queued_at THEN 'new' ELSE 'recurring' END AS recurrence
  FROM findings f
  JOIN domains d       ON d.id = f.domain_id
  JOIN assets a        ON a.id = f.asset_id
  JOIN scoring_rules r ON r.id = f.rule_id
  JOIN data_sources s  ON s.id = f.source_id
  LEFT JOIN scoring_rule_framework_mappings fm ON fm.rule_code = r.code
  LEFT JOIN scans sc   ON sc.id = f.last_scan_id
  LEFT JOIN cves c     ON c.cve_id = f.cve_id
  LEFT JOIN breach_exposures b ON b.finding_id = f.id
  LEFT JOIN LATERAL (SELECT x.severity FROM score_contributions x
                      WHERE x.finding_id = f.id
                        AND x.score_id = (SELECT ds.id FROM domain_scores ds WHERE ds.domain_id = f.domain_id
                                           ORDER BY ds.computed_at DESC LIMIT 1)) sc_score ON true
 WHERE d.fqdn = %s AND f.status = 'open'
 ORDER BY array_position(ARRAY['critical','high','medium','low'], coalesce(sc_score.severity, f.severity)),
                    f.detected_at DESC, f.id
'''


def _finding(f):
    evidence = {k: v for k, v in f['evidence'].items() if k not in ('title', 'caracteristicas', 'huella', 'partes')}
    if f['breach_name']:
        evidence.update(breach_name=f['breach_name'], breach_date=f['breach_date'], data_classes=f['data_classes'])
    return {
        'id': f['id'], 'title': f['evidence'].get('title', f['rule_code']), 'asset': f['asset'], 'asset_type': f['asset_type'],
        'category': f['category'], 'rule_code': f['rule_code'], 'source': f['source'], 'severity': f['severity'],
        'base_severity': f['base_severity'], 'status': f['status'], 'recurrence': f['recurrence'],
        'cve_id': f['cve_id'], 'cvss': float(f['cvss']) if f['cvss'] is not None else None,
        'epss': float(f['epss']) if f['epss'] is not None else None, 'in_kev': f['in_kev'],
        'evidence': evidence, 'caracteristicas': caracteristicas(f),
        'frameworks': _marcos(f),
        'detected_at': f['detected_at'], 'last_scan_id': f['last_scan_id'],
    }


@router.get('/domains/{fqdn}/findings', summary='Hallazgos abiertos del dominio, de más a menos severo')
def domain_findings(fqdn: str, session: Session = Depends(LEE_HALLAZGOS)):
    _domain_id(session, fqdn)
    items = [_finding(f) for f in _query(session, FINDINGS_SQL, (fqdn,))]
    return {'domain': fqdn, 'items': items, 'total': len(items)}


# ---------------------------------------------------------------- score e histórico

SCORES_SQL = '''
SELECT ds.id::text AS score_id, ds.scan_id::text, ds.score, ds.category_scores, ds.method, ds.reason, ds.partial_coverage,
    ds.model_version, ds.model_fallback_reason, ds.computed_at,
    rs.version AS rule_set_version, rs.category_weights, rs.band_medium_from, rs.band_high_from, rs.band_critical_from,
    sc.stats, sc.queued_at, sc.finished_at,
       (SELECT count(*) FROM score_contributions x WHERE x.score_id = ds.id AND x.severity = 'critical') AS critical_at_time
  FROM domain_scores ds
  JOIN domains d ON d.id = ds.domain_id
  JOIN scoring_rule_sets rs ON rs.id = ds.rule_set_id
  LEFT JOIN scans sc ON sc.id = ds.scan_id
 WHERE d.fqdn = %s
 ORDER BY ds.computed_at
'''


SCORE_APORTES_SQL = '''
SELECT r.code, r.category, x.severity, x.penalty
  FROM score_contributions x JOIN scoring_rules r ON r.id = x.rule_id
 WHERE x.score_id = %s::uuid
'''

SCORE_CORRIDAS_SQL = '''
SELECT ds.code AS source, r.status, r.raw_payload->'sin_cobertura' AS sin_cobertura,
       r.raw_payload->'sin_llave' AS sin_llave, r.raw_payload->'avisos' AS avisos
  FROM scan_source_runs r JOIN data_sources ds ON ds.id = r.source_id
 WHERE r.scan_id = %s::uuid
'''


def _score_base(row, critical_open):
    weights = {k: float(v) for k, v in row['category_weights'].items()}
    cortes = configuracion.cortes_de_fila(row)   # los del juego de este score (RC-237)
    calc = criterio.score_dominio(row['category_scores'], weights, critical_open, cortes)
    return {
        'score_id': row['score_id'], 'score': row['score'], 'band': criterio.banda(row['score'], cortes),
        'grade': criterio.letra(row['score'], cortes),
        'weighted': calc['ponderado'], 'floor': calc['piso'], 'floor_applied': row['score'] > calc['ponderado'],
        'critical_open': critical_open, 'method': row['method'], 'rule_set_version': row['rule_set_version'],
        'reason': row['reason'], 'partial_coverage': row['partial_coverage'], 'computed_at': row['computed_at'],
        'floor_message': motor.mensaje_piso(calc, critical_open),
        'model_version': row['model_version'], 'model_fallback_reason': row['model_fallback_reason'],
    }, weights


@router.get('/domains/{fqdn}/score', summary='Score más reciente con su desglose por categoría')
def domain_score(fqdn: str, session: Session = Depends(session_or_api_key)):
    domain_id = _domain_id(session, fqdn)
    # REPEATABLE READ, como _reporte: el score y los críticos de ahora salen de una sola foto, así un score que el
    # orquestador guarda a la mitad no da needs_rescan sin hacer falta (RC-316).
    with transaction(session.org_id, isolation=IsolationLevel.REPEATABLE_READ) as conn:
        rows = conn.execute(SCORES_SQL, (fqdn,)).fetchall()
        if not rows:
            raise HTTPException(404, 'El dominio aún no tiene score')
        # En un score 'ml', score_contributions guarda la severidad que predijo el modelo (_guardar_score del
        # orquestador), no la de findings. Un hallazgo vigente con aporte en este score se juzga con esa severidad y
        # uno sin aporte, con la de findings: así un crítico que el modelo predijo high no deja needs_rescan en true
        # para siempre. Con 'rules' es la de findings, como siempre (RC-316).
        criticos_ahora = {r['id'] for r in conn.execute(
            'SELECT f.id FROM findings f '
            'LEFT JOIN score_contributions x ON x.finding_id = f.id AND x.score_id = %s::uuid '
            'WHERE f.domain_id = %s AND f.status = ANY(%s) '
            "AND CASE WHEN %s::text = 'ml' THEN coalesce(x.severity, f.severity) ELSE f.severity END = 'critical'",
            (rows[-1]['score_id'], domain_id, list(criterio.ESTADOS_VIGENTES), rows[-1]['method'])).fetchall()}
        criticos_del_score = {r['finding_id'] for r in conn.execute(
            "SELECT finding_id FROM score_contributions WHERE score_id = %s::uuid AND severity = 'critical'",
            (rows[-1]['score_id'],)).fetchall()}
        threshold = conn.execute('SELECT alert_score_threshold AS t FROM organizations').fetchone()['t']
        # Subcategorías y KRI (#114): los aportes de este score y las corridas de su escaneo, sin columnas nuevas.
        aportes = conn.execute(SCORE_APORTES_SQL, (rows[-1]['score_id'],)).fetchall()
        filas_corridas = conn.execute(SCORE_CORRIDAS_SQL, (rows[-1]['scan_id'],)).fetchall()
    corridas = {r['source']: r['status'] for r in filas_corridas}
    # El piso y su mensaje explican el score guardado con los críticos de su snapshot, como el histórico. Los de
    # ahora van aparte en critical_open y needs_rescan avisa cuando ya no son los mismos hallazgos, no solo cuando
    # cambia la cuenta: una brecha resuelta más un crítico nuevo da 1 contra 1 y sí pide escaneo (RC-316).
    critical_at_time = rows[-1]['critical_at_time']
    base, weights = _score_base(rows[-1], critical_at_time)
    base.update(critical_open=len(criticos_ahora), critical_at_time=critical_at_time,
                needs_rescan=criticos_ahora != criticos_del_score)
    stats = rows[-1]['stats'] or {}
    subs, kris = subcategorias.resumen(aportes, corridas, stats.get('rules_without_coverage') or (),
                                       stats.get('sources_partial') or ())
    # Los códigos que el escaneo del score no revisó, con su fuente y su motivo, para que el portal los nombre (RC-229).
    huecos = cobertura.huecos(filas_corridas, stats.get('rules_without_coverage') or (),
                              stats.get('sources_partial') or ())
    cortes = configuracion.cortes_de_fila(rows[-1])
    categories = [{'category': c, 'score': rows[-1]['category_scores'][c],
                   'band': criterio.banda(rows[-1]['category_scores'][c], cortes),
                   'weight': weights[c]} for c in criterio.CATEGORIAS]
    return {'domain': fqdn, **base, 'categories': categories,
            'subcategories': subs, 'kris': kris, 'kri_map_version': subcategorias.VERSION,
            'coverage_gaps': huecos,
            'alert': {'threshold': threshold, 'triggered': criterio.dispara_alerta(base['score'], threshold)}}


@router.get('/domains/{fqdn}/score/history', summary='Todos los scores del dominio, del más viejo al más nuevo')
def score_history(fqdn: str, session: Session = Depends(session_or_api_key)):
    _domain_id(session, fqdn)
    rows = _query(session, SCORES_SQL, (fqdn,))
    scan_ids = [row['scan_id'] for row in rows if row['reason'] == 'scan']
    nuevos_activos = {}
    if scan_ids:
        nuevos_activos = {
            row['scan_id']: row['new_assets']
            for row in _query(session, '''
                SELECT s.id::text AS scan_id, count(a.id) AS new_assets
                  FROM scans s
                  LEFT JOIN assets a ON a.domain_id = s.domain_id
                                    AND a.first_seen_at >= s.queued_at
                                    AND a.first_seen_at <= s.finished_at
                 WHERE s.id::text = ANY(%s)
                 GROUP BY s.id
            ''', (scan_ids,))
        }
    items = []
    escaneo_anterior = None
    for row in rows:
        base, _ = _score_base(row, row['critical_at_time'])
        # Un recálculo no encuentra ni resuelve hallazgos. Un escaneo que no los contó (antes de RC-55) da null, no 0.
        stats = (row['stats'] or {}) if row['reason'] == 'scan' else {'new_findings': 0, 'resolved_findings': 0}
        cambios_semanales = None
        if row['reason'] == 'scan':
            escaneo = {**row, 'new_assets': nuevos_activos.get(row['scan_id'], 0)}
            cambios_semanales = cambios.resumen_semanal(escaneo, escaneo_anterior)
            escaneo_anterior = escaneo
        items.append({**base, 'categories': row['category_scores'],
                      'new_findings': stats.get('new_findings'), 'resolved_findings': stats.get('resolved_findings'),
                      'weekly_changes': cambios_semanales})
    return {'domain': fqdn, 'items': items, 'total': len(items)}


# ---------------------------------------------------------------- comparación y exportaciones (#24, RC-57)
# Las tres piden autorización firmada vigente (retro-11), como la exportación del plan de acción (RC-307): un dominio
# de otra empresa responde 404, como en el resto de la API, y uno de la empresa sin autorización vigente responde 403.

def _dominio_autorizado(session, fqdn):
    rows = _query(session, '''
        SELECT d.id::text,
               EXISTS (SELECT 1 FROM domain_authorizations a
                        WHERE a.domain_id = d.id AND a.revoked_at IS NULL
                          AND current_date BETWEEN a.valid_from AND a.valid_until) AS vigente
          FROM domains d WHERE d.fqdn = %s
    ''', (fqdn,))
    if not rows or not in_scope(session, rows[0]['id']):
        raise HTTPException(404, 'Dominio no encontrado para esta organización')
    if not rows[0]['vigente']:
        raise HTTPException(403, 'El dominio no tiene una autorización firmada vigente')
    return rows[0]['id']


def _carta_vigente(conn, domain_id):
    """Vuelve a revisar la carta dentro de la transacción que lee los datos, como _reporte(): si venció o se revocó
    después de _dominio_autorizado(), responde 403 y la exportación no deja evento (RC-312)."""
    if not conn.execute('SELECT 1 FROM domain_authorizations WHERE domain_id = %s AND revoked_at IS NULL '
                        'AND current_date BETWEEN valid_from AND valid_until LIMIT 1', (domain_id,)).fetchone():
        raise HTTPException(403, 'El dominio no tiene una autorización firmada vigente')


def _formato(formato):
    if formato not in ('csv', 'json'):
        raise HTTPException(422, "El formato debe ser 'csv' o 'json'")
    return formato


def _descarga(contenido, media_type, nombre):
    return Response(content=contenido, media_type=media_type,
                    headers={'Content-Disposition': 'attachment; filename="%s"' % nombre})


def _json(data):
    return json.dumps(jsonable_encoder(data), ensure_ascii=False, separators=(',', ':'))


ENCABEZADOS_HALLAZGOS = (
    'dominio', 'hallazgo_id', 'titulo', 'severidad', 'severidad_base', 'categoria', 'regla', 'activo',
    'tipo_activo', 'fuente', 'estado', 'recurrencia', 'cve', 'cvss', 'epss', 'en_kev', 'detectado',
    'ultimo_escaneo_id', 'mitre_attack', 'iso_27001_2022', 'cis_controls_v8_1', 'evidencia',
)


REPORTE_DESCARGADO = 'report.downloaded'


def _registrar_descarga(conn, session, request, tipo, formato, domain_id, filas):
    """Deja la descarga en la bitácora (#194, RC-312) con la acción report.downloaded de db/cirdan_esquema.dbml.

    Va en la transacción que leyó los datos y antes de devolverlos: si audit() falla, la transacción se deshace y la
    petición responde 500 sin descarga. Cualquier ruta de descarga de reporte que llegue (el PDF de reports u otra)
    usa esta misma acción con su tipo en details, así la bitácora (RC-130) filtra todas las descargas por una acción.
    details lleva tipo, formato, dominio y número de filas, nunca lo exportado. El dominio sale de la base y no de la
    ruta: fqdn es citext y la ruta acepta ACME-Demo.MX, pero details es jsonb y un filtro por dominio compara texto
    exacto. audit() agrega además api_key_id si pidió una llave de API o platform_user_id si fue un superadmin en una
    empresa ajena. El actor es el usuario de la sesión, ese superadmin o la llave, con la IP de la petición.

    La transacción va en READ COMMITTED, como las tres de aquí: audit() no acepta REPEATABLE READ ni SERIALIZABLE,
    porque el trigger de la cadena leería el último eslabón con la foto vieja y dos descargas a la vez chocarían. El
    PDF de reports lee en REPEATABLE READ (_reporte): antes de registrar su descarga hay que cambiar eso o el trigger."""
    dominio = conn.execute('SELECT fqdn::text FROM domains WHERE id = %s', (domain_id,)).fetchone()['fqdn']
    audit(conn, session.org_id, REPORTE_DESCARGADO, user_id=session.audit_user_id, ip=client_ip(request),
          entity_type='domain', entity_id=domain_id, platform=session.audit_platform, api_key_id=session.api_key_id,
          details={'kind': tipo, 'format': formato, 'domain': dominio, 'rows': filas})


@router.get('/domains/{fqdn}/findings/export', summary='Descarga los hallazgos abiertos del dominio en CSV o JSON')
def export_findings(request: Request, fqdn: str, formato: str = Query(default='json'),
                    session: Session = Depends(LEE_HALLAZGOS)):
    formato = _formato(formato)
    domain_id = _dominio_autorizado(session, fqdn)
    with transaction(session.org_id) as conn:
        _carta_vigente(conn, domain_id)
        items = [_finding(f) for f in conn.execute(FINDINGS_SQL, (fqdn,)).fetchall()]
        if formato == 'json':
            respuesta = _descarga(_json({'domain': fqdn, 'items': items, 'total': len(items)}),
                                  'application/json; charset=utf-8', '%s-hallazgos.json' % fqdn)
        else:
            filas = [(fqdn, i['id'], i['title'], i['severity'], i['base_severity'], i['category'], i['rule_code'],
                      i['asset'], i['asset_type'], i['source'], i['status'], i['recurrence'], i['cve_id'], i['cvss'],
                      i['epss'], i['in_kev'], i['detected_at'], i['last_scan_id'],
                      i['frameworks']['mitre_attack']['technique_id'], i['frameworks']['iso_27001_2022']['control_id'],
                      i['frameworks']['cis_controls_v8_1']['safeguard_id'], i['evidence']) for i in items]
            respuesta = _descarga(csv_con_bom(ENCABEZADOS_HALLAZGOS, filas), 'text/csv; charset=utf-8',
                                  '%s-hallazgos.csv' % fqdn)
        _registrar_descarga(conn, session, request, 'findings', formato, domain_id, len(items))
    return respuesta


# ---------------------------------------------------------------- reporte ejecutivo (#45, RC-70)
# Pide la misma autorización vigente que las exportaciones: 403 sin carta vigente, 404 de otra empresa.

REPORTE_DOMINIO_SQL = '''
SELECT d.last_scan_at, o.name AS organization, a.valid_from, a.valid_until
  FROM domains d
  JOIN organizations o ON o.id = d.organization_id
  JOIN LATERAL (SELECT x.valid_from, x.valid_until FROM domain_authorizations x
                 WHERE x.domain_id = d.id AND x.revoked_at IS NULL
                   AND current_date BETWEEN x.valid_from AND x.valid_until
                 ORDER BY x.valid_until DESC LIMIT 1) a ON true
 WHERE d.id = %s
'''


def _reporte(session, fqdn):
    domain_id = _dominio_autorizado(session, fqdn)
    # REPEATABLE READ, como la salida a SIEM: score, hallazgos y carta salen de una sola foto de la base, así un
    # escaneo que cierra a la mitad no mezcla el score de uno con los hallazgos del otro.
    with transaction(session.org_id, isolation=IsolationLevel.REPEATABLE_READ) as conn:
        dominio = conn.execute(REPORTE_DOMINIO_SQL, (domain_id,)).fetchone()
        if dominio is None:  # la carta venció o se revocó entre las dos lecturas
            raise HTTPException(403, 'El dominio no tiene una autorización firmada vigente')
        scores = conn.execute(SCORES_SQL, (fqdn,)).fetchall()
        hallazgos = [_finding(f) for f in conn.execute(FINDINGS_SQL, (fqdn,)).fetchall()]
        codigos = sorted({h['rule_code'] for h in hallazgos})
        recomendaciones = {r['code']: r['recommendation'] for r in conn.execute(
            'SELECT code, recommendation FROM scoring_rule_texts WHERE code = ANY(%s)', (codigos,)).fetchall()}
    score = None
    if scores:
        s = scores[-1]
        cortes = configuracion.cortes_de_fila(s)
        score = {'score': s['score'], 'band': criterio.banda(s['score'], cortes),
                 'grade': criterio.letra(s['score'], cortes),
                 'partial_coverage': s['partial_coverage'], 'computed_at': s['computed_at']}
    return reporte.armar(fqdn, dominio['organization'],
                         {'valid_from': dominio['valid_from'], 'valid_until': dominio['valid_until']},
                         score, dominio['last_scan_at'], hallazgos, recomendaciones)


@router.get('/domains/{fqdn}/report', summary='Reporte ejecutivo del dominio en JSON (para el PDF del portal) o en HTML')
def executive_report(response: Response, fqdn: str, formato: str = Query(default='json'),
                     session: Session = Depends(session_or_api_key)):
    if formato not in ('json', 'html'):
        raise HTTPException(422, "El formato debe ser 'json' o 'html'")
    datos = _reporte(session, fqdn)
    # Trae hallazgos, activos, empresa y fechas de la carta: ni el navegador ni un proxy lo guardan, como la SIEM.
    if formato == 'json':
        response.headers['Cache-Control'] = 'no-store'
        return datos
    # Sin scripts ni recursos externos. La CSP lleva frame-ancestors para que el middleware de RC-283 la conserve.
    respuesta = _descarga(reporte.html(datos), 'text/html; charset=utf-8', '%s-resumen-ejecutivo.html' % fqdn)
    respuesta.headers['Content-Security-Policy'] = reporte.CSP_HTML
    respuesta.headers['Cache-Control'] = 'no-store'
    return respuesta


COMPARE_SCORES_SQL = '''
SELECT ds.id::text AS score_id, ds.scan_id::text, ds.score, ds.reason, ds.partial_coverage, ds.computed_at
  FROM domain_scores ds WHERE ds.domain_id = %s AND ds.id = ANY(%s::uuid[])
'''

# El aporte (severidad, puntos y regla) es del score del dominio y siempre sale. El título, el activo y
# el estado se leen del hallazgo de hoy, y el upsert por huella puede haberlo movido a otro dominio de
# la empresa: una llave de un solo dominio (%(solo)s) no los recibe de un hallazgo que ya no es suyo.
COMPARE_CONTRIBUTIONS_SQL = '''
SELECT x.score_id::text, f.id::text AS finding_id, x.severity, x.penalty,
       CASE WHEN v.visible THEN coalesce(f.evidence->>'title', r.code) ELSE r.code END AS title,
       r.code AS rule_code, r.category,
       CASE WHEN v.visible THEN a.value END AS asset,
       CASE WHEN v.visible THEN a.asset_type END AS asset_type,
       CASE WHEN v.visible THEN f.status END AS status
  FROM score_contributions x
  JOIN domain_scores ds ON ds.id = x.score_id
  JOIN findings f       ON f.id = x.finding_id  -- sin f.domain_id: el upsert por huella puede haberlo movido
  JOIN assets a         ON a.id = f.asset_id
  JOIN scoring_rules r  ON r.id = x.rule_id
 CROSS JOIN LATERAL (SELECT %(solo)s::uuid IS NULL OR f.domain_id = %(solo)s::uuid AS visible) v
 WHERE ds.domain_id = %(domain_id)s AND x.score_id = ANY(%(scores)s::uuid[])
'''


def _score_ids(*valores):
    try:
        return [str(uuid.UUID(v)) for v in valores]
    except ValueError:
        raise HTTPException(404, 'Escaneo no encontrado')  # un id mal formado se responde igual que uno ajeno


def _comparacion(session, fqdn, desde, hasta, descargar=None):
    """La comparación. Con `descargar(conn, data, domain_id)` devuelve lo que esa función arme dentro de la misma
    transacción, para que la exportación escriba su evento en la bitácora antes de que se confirme."""
    domain_id = _dominio_autorizado(session, fqdn)
    desde, hasta = _score_ids(desde, hasta)
    with transaction(session.org_id) as conn:  # una sola transacción: las dos fotos y sus aportes del mismo momento
        _carta_vigente(conn, domain_id)
        scores = {r['score_id']: r for r in conn.execute(COMPARE_SCORES_SQL, (domain_id, [desde, hasta])).fetchall()}
        if desde not in scores or hasta not in scores:
            raise HTTPException(404, 'Escaneo no encontrado')
        aportes = conn.execute(COMPARE_CONTRIBUTIONS_SQL, {'domain_id': domain_id, 'scores': [desde, hasta],
                                                           'solo': session.domain_id}).fetchall()
        items, resumen = comparacion.comparar([a for a in aportes if a['score_id'] == desde],
                                              [a for a in aportes if a['score_id'] == hasta])
        data = {'domain': fqdn, 'from': scores[desde], 'to': scores[hasta], 'summary': resumen,
                'items': items, 'total': len(items)}
        return descargar(conn, data, domain_id) if descargar else data


@router.get('/domains/{fqdn}/score/compare',
            summary='Compara hallazgo por hallazgo dos scores del histórico: nuevos, que ya no están y que siguen')
def compare_scores(fqdn: str, desde: str = Query(..., description='score_id del histórico'),
                   hasta: str = Query(..., description='score_id del histórico'),
                   session: Session = Depends(LEE_HALLAZGOS)):
    return _comparacion(session, fqdn, desde, hasta)


@router.get('/domains/{fqdn}/score/compare/export', summary='Descarga la comparación de dos scores en CSV o JSON')
def export_comparison(request: Request, fqdn: str, desde: str = Query(...), hasta: str = Query(...),
                      formato: str = Query(default='json'), session: Session = Depends(LEE_HALLAZGOS)):
    formato = _formato(formato)

    def descargar(conn, data, domain_id):
        if formato == 'json':
            respuesta = _descarga(_json(data), 'application/json; charset=utf-8', '%s-comparacion.json' % fqdn)
        else:
            respuesta = _descarga(comparacion.exportar_csv(data), 'text/csv; charset=utf-8',
                                  '%s-comparacion.csv' % fqdn)
        _registrar_descarga(conn, session, request, 'comparison', formato, domain_id, data['total'])
        return respuesta

    return _comparacion(session, fqdn, desde, hasta, descargar)


# ---------------------------------------------------------------- plan de acción y simulador (#42, #70)

def _contexto_plan(session, fqdn):
    domain_id = _domain_id(session, fqdn)
    with transaction(session.org_id) as conn:
        return _leer_contexto_plan(conn, session, domain_id)


def _leer_contexto_plan(conn, session, domain_id):
    """Lee el contexto del plan en la transacción de quien llama, en READ COMMITTED a propósito: la exportación escribe
    ahí su evento y audit() no acepta REPEATABLE READ (_registrar_descarga). Cada lectura depende de una sola cosa que
    cambia: el score se lee primero y lo demás sale de su id (juego de reglas y aportes, que no cambian) o de los
    hallazgos, que el escaneo guarda por fuente en transacciones propias antes de su score. Un commit en medio da lo
    mismo que una foto tomada antes o después de él. El 409 de ML con un escaneo a medias pasa igual con una sola foto."""
    score = conn.execute(
        'SELECT id::text, rule_set_id::text, score, category_scores, method, partial_coverage FROM domain_scores '
        'WHERE domain_id = %s ORDER BY computed_at DESC LIMIT 1', (domain_id,),
    ).fetchone()
    if score:
        rule_set_id, method, parcial = score['rule_set_id'], score['method'], score['partial_coverage']
    else:
        active = configuracion.juego_activo(conn, session.org_id)
        if not active:
            raise HTTPException(409, 'El dominio aún no tiene un juego de reglas activo')
        rule_set_id, method, parcial = active['id'], 'rules', False

    rule_set = conn.execute(
        'SELECT category_weights, band_medium_from, band_high_from, band_critical_from '
        'FROM scoring_rule_sets WHERE id = %s', (rule_set_id,),
    ).fetchone()
    reglas = {r['code']: r for r in conn.execute(
        'SELECT r.id::text, r.code, r.category, r.base_severity, r.weight, r.max_penalty, t.recommendation '
        'FROM scoring_rules r JOIN scoring_rule_texts t '
        'ON t.code = r.code WHERE r.rule_set_id = %s',
        (rule_set_id,),
    ).fetchall()}
    hallazgos = conn.execute(
        'SELECT f.id::text AS id, r.code AS rule_code, f.severity, f.status '
        'FROM findings f JOIN scoring_rules r ON r.id = f.rule_id '
        'WHERE f.domain_id = %s AND f.status = ANY(%s) ORDER BY f.id',
        (domain_id, list(motor.ESTADOS_PUNTUABLES)),
    ).fetchall()
    severidades = None
    if method == 'ml' and score:
        severidades = {r['finding_id']: r['severity'] for r in conn.execute(
            'SELECT finding_id::text, severity FROM score_contributions WHERE score_id = %s',
            (score['id'],),
        ).fetchall()}
        faltantes = [h['id'] for h in hallazgos if h['id'] not in severidades]
        if faltantes:
            raise HTTPException(409, 'No hay severidad de ML guardada para todos los hallazgos vigentes')

    pesos = {k: float(v) for k, v in rule_set['category_weights'].items()}
    # El 'Actual' del plan es el score guardado, el mismo que muestra /score. Antes y después llevan los cortes de
    # bandas del juego de ese score (RC-237).
    cortes = configuracion.cortes_de_fila(rule_set)
    guardado = {'score': score['score'], 'category_scores': score['category_scores']} if score else None
    return domain_id, reglas, pesos, hallazgos, method, severidades, parcial, guardado, cortes


def _plan_data(session, fqdn, descargar=None):
    """El plan de acción. Con `descargar(conn, data, domain_id)` devuelve lo que esa función arme dentro de la
    transacción que leyó los datos, como en _comparacion()."""
    domain_id = _domain_id(session, fqdn)
    with transaction(session.org_id) as conn:
        if descargar:
            _carta_vigente(conn, domain_id)  # si venció o se revocó tras _dominio_autorizado, 403 y sin evento (RC-312)
        _, reglas, pesos, hallazgos, method, severidades, parcial, guardado, cortes = _leer_contexto_plan(
            conn, session, domain_id)
        try:
            data = plan_accion.construir_plan(fqdn, hallazgos, reglas, pesos, method, severidades, parcial, guardado,
                                              cortes)
        except ValueError as e:
            raise HTTPException(409, str(e)) from e
        return descargar(conn, data, domain_id) if descargar else data


@router.get('/domains/{fqdn}/action-plan', summary='Plan de acción con el impacto estimado por acción')
def action_plan(fqdn: str, session: Session = Depends(session_or_api_key)):
    return _plan_data(session, fqdn)


@router.post('/domains/{fqdn}/action-plan/simulate', summary='Simula una o varias acciones sin guardar cambios')
def simulate_action_plan(fqdn: str, action_ids: list[str] = Body(embed=True),
                         session: Session = Depends(current_session)):
    _, reglas, pesos, hallazgos, method, severidades, parcial, guardado, cortes = _contexto_plan(session, fqdn)
    if not action_ids or len(action_ids) > 100 or any(not isinstance(action_id, str) for action_id in action_ids):
        raise HTTPException(422, 'Selecciona entre 1 y 100 acciones del plan')
    try:
        resultado = plan_accion.simular(hallazgos, reglas, pesos, action_ids, severidades, guardado, cortes)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    resultado['domain'] = fqdn
    resultado['action_ids'] = action_ids
    resultado['partial_coverage'] = parcial
    resultado['method'] = method
    return resultado


@router.get('/domains/{fqdn}/action-plan/export', summary='Descarga el plan de acción en CSV o JSON')
def export_action_plan(request: Request, fqdn: str, formato: str = Query(default='json'),
                       session: Session = Depends(session_or_api_key)):
    formato = _formato(formato)
    _dominio_autorizado(session, fqdn)  # 404 de otra empresa y 403 sin carta vigente, antes de leer el plan (RC-307)

    def descargar(conn, data, domain_id):
        if formato == 'csv':
            respuesta = _descarga(plan_accion.exportar_csv(data), 'text/csv; charset=utf-8', '%s-plan.csv' % fqdn)
        else:
            respuesta = _descarga(plan_accion.exportar_json(data), 'application/json; charset=utf-8',
                                  '%s-plan.json' % fqdn)
        _registrar_descarga(conn, session, request, 'action_plan', formato, domain_id, len(data['actions']))
        return respuesta

    return _plan_data(session, fqdn, descargar)


# ---------------------------------------------------------------- salida a SIEM (#98, RC-212)
# Consultas propias y no las del portal: de la evidencia solo leen sus llaves 'cve' y 'cvss', validadas, y el valor de
# un activo de tipo email no sale de la base.

SIEM_FINDINGS_SQL = '''
WITH ultimos AS (SELECT ds.id, ds.computed_at, row_number() OVER (ORDER BY ds.computed_at DESC, ds.id) AS n
                   FROM domain_scores ds JOIN domains dd ON dd.id = ds.domain_id
                   LEFT JOIN scans ss ON ss.id = ds.scan_id
                  WHERE dd.fqdn = %(fqdn)s AND ds.reason = 'scan'
                    AND ss.stats->'sources_ok' IS DISTINCT FROM '0'::jsonb
                  ORDER BY ds.computed_at DESC, ds.id LIMIT 2),
     caidos AS (SELECT r.source_id FROM scans cs JOIN domains dd ON dd.id = cs.domain_id
                  JOIN scan_source_runs r ON r.scan_id = cs.id AND r.status = 'succeeded'
                 WHERE dd.fqdn = %(fqdn)s AND cs.finished_at IS NOT NULL
                   AND cs.finished_at > (SELECT min(u.computed_at) FROM ultimos u)
                   AND NOT EXISTS (SELECT 1 FROM domain_scores x WHERE x.scan_id = cs.id))
SELECT f.id::text, t.title AS rule_title, r.code AS rule_code, r.category,
       coalesce(sc_score.severity, f.severity) AS severity, f.status, cv.cve_id,
       coalesce(c.cvss_base_score, CASE WHEN jsonb_typeof(f.evidence->'cvss') = 'number' THEN
           CASE WHEN (f.evidence->>'cvss')::numeric BETWEEN 0 AND 10 THEN (f.evidence->>'cvss')::numeric END END)
           AS cvss,
       (SELECT x.severity FROM score_contributions x
         WHERE x.finding_id = f.id AND x.score_id = (SELECT u.id FROM ultimos u WHERE u.n = 2)) AS previous_severity,
       CASE WHEN a.asset_type = 'email' THEN NULL ELSE a.value END AS asset, a.asset_type,
       host(a.ip_address) AS asset_ip,
       CASE WHEN pa.asset_type IN ('domain','subdomain') THEN pa.value END AS asset_parent,
       fm.attack_technique_id, s.code AS data_source, f.detected_at, f.last_scan_id::text,
       sc.finished_at AS scan_finished_at,
       CASE WHEN (SELECT count(*) FROM score_contributions x
                   WHERE x.finding_id = f.id AND x.score_id IN (SELECT u.id FROM ultimos u)) = 2
                 AND f.source_id NOT IN (SELECT k.source_id FROM caidos k)
            THEN 'recurring' ELSE 'new' END AS recurrence
  FROM findings f
  JOIN domains d       ON d.id = f.domain_id
  JOIN assets a        ON a.id = f.asset_id
  LEFT JOIN assets pa  ON pa.id = a.parent_asset_id
  JOIN scoring_rules r ON r.id = f.rule_id
  JOIN scoring_rule_texts t ON t.code = r.code
  JOIN data_sources s  ON s.id = f.source_id
  LEFT JOIN scoring_rule_framework_mappings fm ON fm.rule_code = r.code
  LEFT JOIN scans sc   ON sc.id = f.last_scan_id
  CROSS JOIN LATERAL (SELECT coalesce(f.cve_id, CASE WHEN f.evidence->>'cve' ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
                                                     THEN f.evidence->>'cve' END) AS cve_id) cv
  LEFT JOIN cves c     ON c.cve_id = cv.cve_id
  LEFT JOIN LATERAL (SELECT x.severity FROM score_contributions x
                      WHERE x.finding_id = f.id
                        AND x.score_id = (SELECT ds.id FROM domain_scores ds WHERE ds.domain_id = f.domain_id
                                           ORDER BY ds.computed_at DESC LIMIT 1)) sc_score ON true
 WHERE d.fqdn = %(fqdn)s AND f.status = 'open'
 ORDER BY array_position(ARRAY['critical','high','medium','low'], coalesce(sc_score.severity, f.severity)),
          f.detected_at DESC, f.id
'''
# recurrence: cada score de escaneo guarda en score_contributions un aporte por hallazgo vigente (open o accepted_risk),
# así que un hallazgo que está en los dos últimos scores de escaneo del dominio ya venía de antes ('recurring') y
# cualquier otro es 'new': uno que apareció o se reabrió en el último escaneo, o después de su score. No usa
# detected_at, que no cambia al reabrir, ni last_scan_id, que no avanza si la fuente del hallazgo falla. Los scores con
# otro motivo (correction, intel_update, rules_change) no cuentan, ni el de un escaneo en el que no respondió ninguna
# fuente (stats.sources_ok = 0): guarda score, pero ninguna fuente confirmó sus hallazgos.
# Se mide contra los escaneos y no contra la exportación anterior: con dos escaneos entre dos exportaciones, un crítico
# que abrió el primero ya sale recurring en la segunda. La alerta de un crítico nuevo solo sale antes del siguiente
# escaneo con score que cuente (el de ultimos, con sources_ok distinto de 0, y tras un escaneo caído hasta el segundo,
# ver abajo). El envío automático al cerrar cada escaneo (#98b, RC-213) es el que no pierde ninguna.
# previous_severity es la severidad del hallazgo en el más viejo de los dos scores: un crítico que no lo era ahí (lo
# subió el ML o el motor) también es alerta (cirdan/siem/__init__.py), aunque siga abierto. La severidad que se compara
# sale del último score de cualquier motivo, así que también alerta un crítico que subió en el score de un escaneo
# con sources_ok = 0, que ultimos no cuenta, o porque el ML cayó a reglas con severidad base critical. Un score
# rules_change no sube nada por sí solo: recalcular_scores (cirdan/score/configuracion.py) copia la severidad ML
# congelada del score anterior o f.severity, así que solo arrastra la subida de un score anterior o el f.severity
# que dejó un escaneo caído (el upsert del orquestador la reescribe aunque el escaneo no deje score). Esas alertas se
# repiten: la del escaneo con sources_ok = 0 otra vez tras el siguiente escaneo con score que cuente, y la del ML cada
# vez que vuelve a caer a reglas. En uno que sigue abierto, todas dependen de que no fuera critical en el más viejo de
# los dos scores de ultimos (previous_severity): si ya lo era (critical ahí, high en el siguiente y otra vez critical
# en uno con sources_ok = 0), la subida ni alerta ni se repite. Al revés, un score que baja la severidad sin un
# escaneo que cuente (el de un escaneo con sources_ok = 0) cierra antes la ventana de un crítico nuevo: si nadie
# exportó entre los dos, esa alerta se pierde.
# Un escaneo que terminó sin score (abandonar_vencidos o marcar_fallido) no deja foto, pero sus fuentes que respondieron
# ya guardaron: pudieron cerrar un hallazgo que el siguiente escaneo reabrió, y el reabrir no deja rastro (el upsert del
# orquestador limpia resolved_at). Por eso, si después del más viejo de esos dos scores terminó un escaneo así (se mide
# con finished_at: queued_at es de antes de la consulta TXT y puede quedar antes del score anterior) en el que la
# fuente del hallazgo respondió ('caidos'), el hallazgo sale 'new': se prefiere repetir una alerta a perderla. Sale así
# hasta el segundo escaneo con score que siga, y un crítico que abrió el escaneo caído alerta otra vez después del
# siguiente. Una fuente que falló en el escaneo caído no tocó sus hallazgos y no cuenta.
# Antes de RC-46 el orquestador no llenaba findings.cve_id y la CVE quedaba solo en evidence['cve']: por eso el
# coalesce. El CVSS sale de la tabla cves o, si esa tabla no tiene su CVSS (una CVE que trae Shodan entra sin CVSS
# hasta el cargador diario, #69, salvo que ya estuviera completa: el orquestador inserta con ON CONFLICT DO NOTHING),
# de evidence['cvss'] cuando es un número de 0 a 10, con la misma expresión que el portal
# (FINDINGS_SQL). La diferencia es la CVE que se busca en cves: aquí la combinada (cve_id o evidence['cve']) y en el
# portal solo f.cve_id. De la evidencia no se lee nada más.
# La severidad sale del último score del dominio y no del último que contó el hallazgo: uno resuelto y reabierto
# después de ese score lleva su severidad de regla y no la de un score viejo.
SIEM_SCAN_SQL = '''
SELECT s.id::text, s.status, s.trigger_type AS trigger, s.queued_at, s.finished_at, s.stats,
       coalesce((SELECT jsonb_agg(jsonb_build_object('data_source', ds.code, 'status', r.status) ORDER BY ds.code)
                   FROM scan_source_runs r JOIN data_sources ds ON ds.id = r.source_id WHERE r.scan_id = s.id), '[]') AS sources
  FROM scans s JOIN domains d ON d.id = s.domain_id
 WHERE d.fqdn = %s AND s.finished_at IS NOT NULL
 ORDER BY s.finished_at DESC LIMIT 1
'''
SIEM_EN_CURSO_SQL = '''
SELECT 1 FROM scans s JOIN domains d ON d.id = s.domain_id WHERE d.fqdn = %s AND s.status IN ('queued','running') LIMIT 1
'''
SIEM_SCORE_SQL = '''
SELECT ds.id::text, ds.scan_id::text, ds.score, ds.category_scores, ds.method, ds.model_version, ds.reason,
       ds.partial_coverage, ds.computed_at, rs.version AS rule_set_version, rs.band_medium_from, rs.band_high_from, rs.band_critical_from
  FROM domain_scores ds
  JOIN domains d ON d.id = ds.domain_id
  JOIN scoring_rule_sets rs ON rs.id = ds.rule_set_id
 WHERE d.fqdn = %s
 ORDER BY ds.computed_at DESC LIMIT 1
'''
# Como en el login (004_login_lookup_seguro.sql): una empresa suspendida o cancelada no exporta aunque su sesión siga viva.
SIEM_PLAN_SQL = '''
SELECT o.status, p.api_and_siem FROM organizations o JOIN plans p ON p.id = o.plan_id
'''
SIEM_SIN_PLAN = 'El plan de la empresa no incluye la salida a SIEM'
SIEM_EMPRESA_INACTIVA = 'La empresa está suspendida o cancelada: no puede exportar a SIEM'


@router.get('/domains/{fqdn}/export/siem',
            summary='Descarga en NDJSON para el HEC de Splunk los hallazgos abiertos, el último escaneo y el último score')
def export_siem(fqdn: str, session: Session = Depends(current_session)):
    # REPEATABLE READ: las consultas ven una sola foto, así un escaneo que cierra a la mitad no mezcla dos escaneos.
    # Con uno activo esa foto ya traería lo que guardaron sus fuentes (cada una confirma sola, en el orquestador) junto
    # al escaneo y al score anteriores: no se exporta hasta que cierre o lo den por caído, con los mismos estados que el
    # índice único de scans. Uno sin marca de vida en 30 minutos (la API se reinició a mitad) se da por caído antes, como
    # en GET /scans, en su propia transacción READ COMMITTED: dentro de la foto, el UPDATE chocaría con la marca de vida
    # que el escaneo escribió después (error de serialización) en vez de esperarla.
    with transaction(session.org_id) as conn:
        # Como al crear una llave (cirdan/api/llaves.py): la sesión dura hasta 8 h, así que una cuenta desactivada
        # después de iniciarla ya no exporta. Responde 401 y la sesión se borra.
        # Un superadmin en una empresa ajena no se ve con esta RLS: su cuenta ya la revisó current_session() con
        # is_platform_admin(), que también pide que siga activa (RC-332).
        if not session.acting_elsewhere and not conn.execute('SELECT 1 FROM users WHERE id = %s AND is_active',
                                                             (session.user_id,)).fetchone():
            sessions.delete(session.token)
            raise HTTPException(401, SIN_SESION)
        plan = conn.execute(SIEM_PLAN_SQL).fetchone()
        if plan and plan['status'] not in ('trial', 'active'):
            raise HTTPException(403, SIEM_EMPRESA_INACTIVA)
        if not plan or not plan['api_and_siem']:
            raise HTTPException(403, SIEM_SIN_PLAN)
        dominio = conn.execute('SELECT id::text FROM domains WHERE fqdn = %s', (fqdn,)).fetchone()
        if dominio:
            orquestador.abandonar_vencidos(conn, session.org_id, domain_id=dominio['id'])
    with transaction(session.org_id, isolation=IsolationLevel.REPEATABLE_READ) as conn:
        dominio = conn.execute('SELECT fqdn::text, now() AS ahora FROM domains WHERE fqdn = %s', (fqdn,)).fetchone()
        if not dominio:
            raise HTTPException(404, 'Dominio no encontrado para esta organización')
        if conn.execute(SIEM_EN_CURSO_SQL, (fqdn,)).fetchone():
            raise HTTPException(409, 'Hay un escaneo en curso del dominio: exporta cuando termine')
        hallazgos = conn.execute(SIEM_FINDINGS_SQL, {'fqdn': fqdn}).fetchall()
        escaneo = conn.execute(SIEM_SCAN_SQL, (fqdn,)).fetchone()
        score = conn.execute(SIEM_SCORE_SQL, (fqdn,)).fetchone()
    fqdn = dominio['fqdn']
    return Response(
        content=siem.ndjson(fqdn, hallazgos, escaneo, score, ahora=dominio['ahora'], export_id=str(uuid.uuid4())),
        media_type='application/x-ndjson; charset=utf-8',
        headers={'Content-Disposition': 'attachment; filename="%s-siem.ndjson"' % fqdn, 'Cache-Control': 'no-store'},
    )


# ---------------------------------------------------------------- explicación

EXPLANATION_SQL = '''
SELECT f.id::text AS finding_id, f.domain_id::text AS domain_id, d.fqdn::text AS domain, f.evidence, coalesce(x.severity, f.severity) AS severity,
       r.base_severity, r.category,
       r.code AS rule_code, r.max_penalty, a.value AS asset, a.asset_type, a.first_seen_at AS asset_first_seen,
       f.detected_at, sc.queued_at AS scan_at, b.breach_date,
       fm.attack_version, fm.attack_technique_id, fm.attack_technique_name,
       fm.attack_source_url, fm.attack_unmapped_reason,
       fm.iso_version, fm.iso_control_id, fm.iso_control_name, fm.iso_source_url,
       fm.cis_version, fm.cis_safeguard_id, fm.cis_safeguard_name, fm.cis_source_url,
    ds.id::text AS score_id, ds.computed_at, ds.method, ds.model_version, ds.model_fallback_reason, x.penalty, x.factors,
       t.title AS rule_title, t.meaning, t.recommendation
  FROM findings f
  JOIN domains d ON d.id = f.domain_id
  JOIN assets a ON a.id = f.asset_id
  JOIN scoring_rules r ON r.id = f.rule_id
  JOIN scoring_rule_texts t ON t.code = r.code
  LEFT JOIN scoring_rule_framework_mappings fm ON fm.rule_code = r.code
  LEFT JOIN scans sc ON sc.id = f.last_scan_id
  LEFT JOIN breach_exposures b ON b.finding_id = f.id
  LEFT JOIN LATERAL (SELECT * FROM domain_scores s WHERE s.domain_id = f.domain_id ORDER BY s.computed_at DESC LIMIT 1) ds ON true
  LEFT JOIN score_contributions x ON x.score_id = ds.id AND x.finding_id = f.id
 WHERE f.id = %s
'''


@router.get('/findings/{finding_id}/explanation', summary='Por qué el hallazgo tiene su severidad y cuánto suma al score')
def finding_explanation(finding_id: str, session: Session = Depends(LEE_HALLAZGOS)):
    try:
        finding_id = str(uuid.UUID(finding_id))
    except ValueError:
        raise HTTPException(404, 'Hallazgo no encontrado')  # un id mal formado se responde igual que uno de otra empresa
    # Sin try: un error de la base (por ejemplo, sin la migración 003) llega al log y responde 500, no 404.
    rows = _query(session, EXPLANATION_SQL, (finding_id,))
    if not rows or not in_scope(session, rows[0]['domain_id']):
        raise HTTPException(404, 'Hallazgo no encontrado')
    f = rows[0]
    factors = [{'label': FACTOR_ES.get(r['label'], r['label']), 'points': r['points']}
               for r in ((f['factors'] or {}).get('rules') or [])]
    return {
        'finding_id': f['finding_id'], 'domain': f['domain'], 'title': f['evidence'].get('title', f['rule_code']),
        'severity': f['severity'], 'base_severity': f['base_severity'], 'category': f['category'], 'rule_code': f['rule_code'],
        'rule_title': f['rule_title'], 'meaning': f['meaning'],
        'score_id': f['score_id'], 'computed_at': f['computed_at'], 'method': f['method'] or 'rules',
        'model_version': f['model_version'], 'model_fallback_reason': f['model_fallback_reason'],
        'penalty': float(f['penalty']) if f['penalty'] is not None else 0.0, 'max_penalty': float(f['max_penalty']),
        'factors': factors, 'caracteristicas': caracteristicas(f),
        'summary': RESUMEN[f['severity']],
        'recommendation': f['recommendation'],
        'frameworks': _marcos(f),
        'confidence': (f['factors'] or {}).get('confidence'),
        'model_prediction': (f['factors'] or {}).get('model_prediction'),
        'explanation_model_version': (f['factors'] or {}).get('explanation_model_version'),
        'shap': (f['factors'] or {}).get('shap'),
    }


# ---------------------------------------------------------------- pesos, activos y escaneos

@router.get('/scoring/weights', summary='Juego de reglas activo: pesos, cortes de bandas, letras, piso, umbral y reglas')
def scoring_weights(session: Session = Depends(session_or_api_key)):
    with transaction(session.org_id) as conn:
        rs = configuracion.juego_activo(conn, session.org_id)
        rules = conn.execute('SELECT r.code, r.category, r.base_severity, r.weight, r.max_penalty, '
                             't.title, t.meaning, t.recommendation FROM scoring_rules r '
                             'JOIN scoring_rule_texts t ON t.code = r.code '
                             'WHERE r.rule_set_id = %s ORDER BY r.id', (rs['id'],)).fetchall()
    cortes = configuracion.cortes_de_fila(rs)
    return {
        'rule_set_version': rs['version'], 'is_active': True, 'activated_at': rs['activated_at'],
        'validated_by': rs['validated_by'], 'category_weights': {k: float(v) for k, v in rs['category_weights'].items()},
        'band_cutoffs': cortes, 'band_cutoffs_template': dict(criterio.CORTES_PLANTILLA),
        'bands': [{'band': c, 'from': d, 'to': h} for d, h, c, _ in criterio.bandas(cortes)],
        'grades': [{'grade': g, 'from': d, 'to': h} for d, h, g in criterio.letras(cortes)],
        'floor': {'one_critical': criterio.piso(1, cortes), 'two_or_more_critical': criterio.piso(2, cortes),
                  'counts_statuses': list(criterio.ESTADOS_VIGENTES)},
        'alert_threshold_default': criterio.UMBRAL_ALERTA,
        'rules': [{**r, 'weight': float(r['weight']), 'max_penalty': float(r['max_penalty'])} for r in rules],
    }


@router.put('/scoring/weights',
            summary='Crea una nueva versión de pesos y cortes de bandas para la organización y recalcula sus scores')
def update_scoring_weights(payload: dict[str, object] = Body(...),
                           session: Session = Depends(require_roles('admin'))):
    try:
        pesos = configuracion.validar_pesos(payload.get('category_weights'))
        # Sin band_cutoffs, la versión nueva copia los de la anterior (RC-237). Con ellos, la misma regla que el CHECK.
        cortes = criterio.validar_cortes(payload['band_cutoffs']) if payload.get('band_cutoffs') is not None else None
    except ValueError as error:
        raise HTTPException(422, str(error)) from error

    with transaction(session.org_id) as conn:
        configuracion.bloquear_pesos(conn, session.org_id)  # el mismo que toma el orquestador al guardar un score
        anterior = configuracion.juego_activo(conn, session.org_id)
        if not anterior:
            raise HTTPException(409, 'No hay un juego de reglas global para usar como plantilla')
        pesos_anteriores = {categoria: float(valor)
                            for categoria, valor in anterior['category_weights'].items()}
        cortes_anteriores = configuracion.cortes_de_fila(anterior)
        cortes = cortes or cortes_anteriores
        if pesos == pesos_anteriores and cortes == cortes_anteriores:
            # Sin versión nueva, pero un dominio cuyo último score salió con otro juego (por ejemplo, de un escaneo
            # que cerró con los pesos de antes) se pone al día con el activo. 'unchanged' solo si no hay ninguno
            # (RC-310). Un dominio ML sin severidades congeladas se salta y se cuenta, en vez de tumbar a los demás
            # con un 409 que se repetiría en cada PUT igual hasta el siguiente escaneo de ese dominio.
            saltados = []
            try:
                recalculados = configuracion.recalcular_scores(conn, session.org_id, anterior['id'], pesos,
                                                               solo_otro_juego=True, saltados=saltados)
            except ValueError as error:  # otro error del motor, como una regla que falta en el juego
                raise HTTPException(409, str(error)) from error
            if recalculados:
                audit(conn, session.org_id, 'scoring.scores_recalculated', user_id=session.audit_user_id,
                      platform=session.audit_platform, entity_type='scoring_rule_set', entity_id=anterior['id'],
                      details={'version': anterior['version'], 'recalculated_domains': recalculados,
                               'skipped_domains': len(saltados), 'skipped_domain_ids': saltados})
            return {
                'rule_set_version': anterior['version'],
                'category_weights': pesos_anteriores,
                'band_cutoffs': cortes_anteriores,
                'recalculated_domains': recalculados,
                'skipped_domains': len(saltados),
                'unchanged': not recalculados,
            }

        version_local = conn.execute(
            'SELECT COALESCE(MAX(version), 0) AS version FROM scoring_rule_sets WHERE organization_id = %s',
            (session.org_id,),
        ).fetchone()['version']
        version = max(int(anterior['version']), int(version_local)) + 1
        conn.execute('UPDATE scoring_rule_sets SET is_active = false '
                     'WHERE organization_id = %s AND is_active', (session.org_id,))
        nuevo = conn.execute(
            'INSERT INTO scoring_rule_sets (organization_id, version, category_weights, is_active, validated_by, '
            'activated_at, band_medium_from, band_high_from, band_critical_from) '
            'VALUES (%s, %s, %s, true, %s, now(), %s, %s, %s) RETURNING id::text',
            (session.org_id, version, Jsonb(pesos), session.author, cortes['medium'], cortes['high'],
             cortes['critical']),
        ).fetchone()['id']
        conn.execute(
            'INSERT INTO scoring_rules (rule_set_id, code, category, base_severity, weight, max_penalty) '
            'SELECT %s, code, category, base_severity, weight, max_penalty FROM scoring_rules WHERE rule_set_id = %s',
            (nuevo, anterior['id']),
        )
        try:
            recalculados = configuracion.recalcular_scores(conn, session.org_id, nuevo, pesos)
        except ValueError as error:
            raise HTTPException(409, str(error)) from error
        audit(conn, session.org_id, 'scoring.weights_changed', user_id=session.audit_user_id,
              platform=session.audit_platform, entity_type='scoring_rule_set', entity_id=nuevo,
              details={'version': version, 'previous_version': anterior['version'],
                       'category_weights': pesos, 'previous_category_weights': pesos_anteriores,
                       'band_cutoffs': cortes, 'previous_band_cutoffs': cortes_anteriores,
                       'recalculated_domains': recalculados})

    return {
        'rule_set_version': version,
        'category_weights': pesos,
        'band_cutoffs': cortes,
        'recalculated_domains': recalculados,
        'skipped_domains': 0,
        'unchanged': False,
    }


@router.get('/domains/{fqdn}/assets', summary='Activos del dominio (provisional, aún no está en el contrato #21)')
def domain_assets(fqdn: str, session: Session = Depends(session_or_api_key)):
    _domain_id(session, fqdn)
    rows = _query(session, '''
        SELECT a.id::text, a.asset_type AS type, a.value, p.value AS parent, a.attributes, a.first_seen_at, a.last_seen_at
          FROM assets a JOIN domains d ON d.id = a.domain_id LEFT JOIN assets p ON p.id = a.parent_asset_id
         WHERE d.fqdn = %s ORDER BY array_position(ARRAY['domain','subdomain','certificate','ip','service','api_doc','email','profile'], a.asset_type), a.value
    ''', (fqdn,))
    return {'items': rows, 'total': len(rows)}


@router.get('/scans', summary='Escaneos de la organización, del más nuevo al más viejo (provisional)')
def scans(domain: str | None = Query(default=None, min_length=1, max_length=253, description='Solo los de este dominio'),
          limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0, le=1_000_000),
          session: Session = Depends(session_or_api_key)):
    with transaction(session.org_id) as conn:
        # uno caído no se muestra en curso. Una llave de un dominio solo toca los de su dominio
        orquestador.abandonar_vencidos(conn, session.org_id, domain_id=session.domain_id)
    # RLS deja solo los de la empresa: un dominio de otra da total 0, no 404. El conteo y la página salen de la misma
    # foto (REPEATABLE READ), así un escaneo que entra a la mitad no descuadra total contra items.
    filtro = '''
          FROM scans s JOIN domains d ON d.id = s.domain_id
         WHERE (%(llave)s::uuid IS NULL OR s.domain_id = %(llave)s::uuid)
           AND (%(fqdn)s::citext IS NULL OR d.fqdn = %(fqdn)s::citext)
    '''
    params = {'llave': session.domain_id, 'fqdn': domain, 'limit': limit, 'offset': offset}
    with transaction(session.org_id, isolation=IsolationLevel.REPEATABLE_READ) as conn:
        total = conn.execute('SELECT count(*) AS n' + filtro, params).fetchone()['n']
        rows = conn.execute('''
        SELECT s.id::text, d.fqdn::text AS domain, s.trigger_type AS trigger, s.status, s.queued_at, s.finished_at, s.stats,
               coalesce((SELECT jsonb_agg(jsonb_build_object('source', ds.code, 'status', r.status, 'attempt', r.attempt,
                                                             'error', r.error, 'finished_at', r.finished_at) ORDER BY ds.code)
                           FROM scan_source_runs r JOIN data_sources ds ON ds.id = r.source_id WHERE r.scan_id = s.id), '[]') AS sources
        ''' + filtro + ' ORDER BY s.queued_at DESC, s.id DESC LIMIT %(limit)s OFFSET %(offset)s', params).fetchall()
    for row in rows:
        row['stats'] = orquestador.stats_publicas(row['stats'])  # sin el costo interno (RC-87)
    return {'items': rows, 'total': total, 'limit': limit, 'offset': offset}

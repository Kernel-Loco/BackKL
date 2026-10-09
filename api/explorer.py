"""Explorador visual de la base `cirdan` para la demo (página /demo).

Todo pasa por el rol `cirdan_app`: los conteos y las filas que se ven son los que
Row-Level Security deja ver al cliente elegido, o ninguno si no hay cliente.
"""
import uuid
from pathlib import Path

import psycopg
from fastapi import Header, HTTPException
from fastapi.responses import HTMLResponse
from psycopg import sql
from psycopg.rows import dict_row

GROUPS = [
    ('Clientes y acceso', ['plans', 'organizations', 'users', 'api_keys']),
    ('Dominios y autorización', ['domains', 'domain_authorizations', 'dns_txt_verifications']),
    ('Escaneos e ingesta', ['data_sources', 'scans', 'scan_source_runs']),
    ('Activos y hallazgos', ['assets', 'findings', 'breach_exposures']),
    ('Inteligencia y score', ['cves', 'scoring_rule_sets', 'scoring_rules', 'domain_scores', 'score_contributions']),
    ('Entrega e integraciones', ['integrations', 'alerts', 'deliveries', 'reports']),
    ('Auditoría', ['audit_log']),
]
TABLES = [t for _, ts in GROUPS for t in ts]
HIDDEN = ('hash', 'secret', '_enc', 'token', 'password', 'raw_payload')


def _tenant(org):
    if not org:
        return None
    try:
        return str(uuid.UUID(org))
    except ValueError:
        raise HTTPException(400, 'X-Organization debe ser el id (uuid) de la organización')


def _short(v):
    if v is None:
        return '—'
    if isinstance(v, uuid.UUID):
        return str(v)[:8] + '…'
    if hasattr(v, 'strftime'):
        return v.strftime('%Y-%m-%d %H:%M') if hasattr(v, 'hour') else v.strftime('%Y-%m-%d')
    s = str(v)
    return s if len(s) <= 42 else s[:41] + '…'


def register(app, dsn):
    def session(org):
        conn = psycopg.connect(dsn, row_factory=dict_row)
        conn.execute("SET TIME ZONE 'America/Mexico_City'")
        if org:
            conn.execute("SELECT set_config('app.current_org', %s, false)", (org,))
        return conn

    @app.get('/demo', include_in_schema=False)
    def demo_page():
        return HTMLResponse(Path(__file__).with_name('demo.html').read_text(encoding='utf-8'))

    @app.get('/db/tables', tags=['base de datos'], summary='Las 23 tablas con las filas que ve el cliente')
    def db_tables(x_organization: str = Header(None, description='Id de la organización; sin él no se ve nada')):
        org = _tenant(x_organization)
        with session(org) as conn:
            rls = {r['relname']: r['relforcerowsecurity'] for r in conn.execute(
                "SELECT relname, relforcerowsecurity FROM pg_class "
                "WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'")}
            name = conn.execute('SELECT name FROM organizations LIMIT 1').fetchone()
            out = []
            for group, tables in GROUPS:
                for t in tables:
                    n = conn.execute(sql.SQL('SELECT count(*) AS n FROM {}').format(sql.Identifier(t))).fetchone()['n']
                    out.append({'group': group, 'table': t, 'rls': bool(rls.get(t)), 'rows': n})
            role = conn.execute('SELECT current_user AS u').fetchone()['u']
        return {'organization': name['name'] if name else None, 'role': role, 'tables': out}

    @app.get('/db/tables/{table}/rows', tags=['base de datos'], summary='Primeras filas visibles de una tabla')
    def db_rows(table: str, x_organization: str = Header(None)):
        if table not in TABLES:
            raise HTTPException(404, 'Tabla no encontrada')
        org = _tenant(x_organization)
        with session(org) as conn:
            cols = [r['column_name'] for r in conn.execute(
                "SELECT attname AS column_name FROM pg_attribute "
                "WHERE attrelid = to_regclass('public.' || quote_ident(%s)) AND attnum > 0 AND NOT attisdropped "
                "AND has_column_privilege(attrelid, attnum, 'SELECT') ORDER BY attnum", (table,))
                if not any(h in r['column_name'] for h in HIDDEN) and r['column_name'] != 'id'][:7]
            orgs = {r['id']: r['name'] for r in conn.execute('SELECT id, name FROM organizations')}
            rows = conn.execute(sql.SQL('SELECT {} FROM {} LIMIT 8').format(
                sql.SQL(', ').join(map(sql.Identifier, cols)), sql.Identifier(table))).fetchall()
        show = lambda c, v: orgs.get(v, _short(v)) if c == 'organization_id' else _short(v)
        return {'table': table, 'columns': cols, 'rows': [[show(c, r[c]) for c in cols] for r in rows]}

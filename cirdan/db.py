"""Conexión a PostgreSQL como el rol de la aplicación `cirdan_app` (sin superusuario ni BYPASSRLS).

Cada transacción fija `app.current_org` con la empresa de quien llama, y Row-Level Security
hace el resto: ninguna consulta filtra por organización a mano.
"""
from contextlib import contextmanager

import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from cirdan.config import config, required

DSN = make_conninfo(host=config('PGHOST', '127.0.0.1'), port=config('PGPORT', '5433'),
                    dbname=config('PGDATABASE', 'cirdan'), user='cirdan_app',
                    password=required('CIRDAN_APP_PASSWORD'))


@contextmanager
def transaction(org=None, isolation=None):
    """Transacción con la zona horaria de México y, si se da, la empresa para RLS.

    `isolation` (psycopg.IsolationLevel) fija el aislamiento antes del BEGIN. Con REPEATABLE_READ todas las consultas
    de la transacción ven la misma foto de la base, como en la salida a SIEM (#98, RC-212). Sin él queda el de la base,
    READ COMMITTED."""
    with psycopg.connect(DSN, row_factory=dict_row) as conn:
        if isolation is not None:
            conn.isolation_level = isolation
        with conn.transaction():
            conn.execute("SET LOCAL TIME ZONE 'America/Mexico_City'")
            if org:
                conn.execute("SELECT set_config('app.current_org', %s, true)", (str(org),))
            yield conn


def audit(conn, org, action, user_id=None, ip=None, entity_type=None, entity_id=None, details=None, platform=None):
    """Agrega un registro a la bitácora; el trigger calcula la cadena de hashes.

    `platform` ({'user_id', 'email'}) es un superadmin que actúa en una empresa ajena (RC-332): queda con actor
    'platform', sin actor_user_id (la FK compuesta pide un usuario de esa empresa) y con su id y correo en details.
    Va con Session.audit_user_id y Session.audit_platform."""
    if platform:
        if user_id:
            raise ValueError('audit(): user_id y platform no van juntos')
        actor = 'platform'
        details = dict(details or {}, platform_user_id=str(platform['user_id']), platform_email=platform['email'])
    else:
        actor = 'user' if user_id else 'system'
    conn.execute(
        'INSERT INTO audit_log (organization_id, actor_type, actor_user_id, action, entity_type, entity_id, ip_address, details) '
        'VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
        (org, actor, user_id, action, entity_type, entity_id, ip, psycopg.types.json.Jsonb(details or {})))

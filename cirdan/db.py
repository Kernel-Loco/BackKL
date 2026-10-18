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
def transaction(org=None):
    """Transacción con la zona horaria de México y, si se da, la empresa para RLS."""
    with psycopg.connect(DSN, row_factory=dict_row) as conn:
        with conn.transaction():
            conn.execute("SET LOCAL TIME ZONE 'America/Mexico_City'")
            if org:
                conn.execute("SELECT set_config('app.current_org', %s, true)", (str(org),))
            yield conn


def audit(conn, org, action, user_id=None, ip=None, entity_type=None, entity_id=None, details=None):
    """Agrega un registro a la bitácora; el trigger calcula la cadena de hashes."""
    conn.execute(
        'INSERT INTO audit_log (organization_id, actor_type, actor_user_id, action, entity_type, entity_id, ip_address, details) '
        'VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
        (org, 'user' if user_id else 'system', user_id, action, entity_type, entity_id, ip,
         psycopg.types.json.Jsonb(details or {})))

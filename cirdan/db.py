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


def audit(conn, org, action, user_id=None, ip=None, entity_type=None, entity_id=None, details=None, platform=None,
          api_key_id=None, operator=None):
    """Agrega un registro a la bitácora; el trigger calcula la cadena de hashes.

    `operator` ({'user_id', 'organization_id'}) es una cuenta 'operator' de la empresa integradora que lee una empresa
    cliente por su delegación (#66, RC-126, migración 033): queda con actor 'operator', sin actor_user_id (la FK
    compuesta pide un usuario de la cliente) y con los dos ids en details. Como con `platform`, el correo no va.

    `platform` ({'user_id'}) es un superadmin que actúa en una empresa ajena (RC-332): queda con actor 'platform',
    sin actor_user_id (la FK compuesta pide un usuario de esa empresa) y solo con su id en details. El correo no va:
    la bitácora de la empresa ajena es de solo inserción y su hash no deja quitar un dato personal después.
    Va con Session.audit_user_id y Session.audit_platform.

    `api_key_id` es la llave de API que hizo la petición (Session.api_key_id): queda con actor 'api_key' y su id en
    details (api_key_id), no en actor_api_key_id. Esa columna tiene FK a api_keys y audit_log no se borra, así que la
    llave ya no se podría borrar nunca (decisión de Ernesto del 17 nov, RC-312).

    No acepta una transacción en REPEATABLE READ ni SERIALIZABLE: audit_log_chain() espera su candado y luego lee el
    último eslabón con la foto de la transacción, que no ve uno confirmado mientras esperaba, y el chain_seq choca con
    UNIQUE (organization_id, chain_seq). En READ COMMITTED cada consulta toma foto nueva y el candado basta."""
    if conn.isolation_level in (psycopg.IsolationLevel.REPEATABLE_READ, psycopg.IsolationLevel.SERIALIZABLE):
        raise ValueError('audit(): la cadena de audit_log pide READ COMMITTED')
    if sum(1 for x in (user_id, platform, api_key_id, operator) if x) > 1:
        raise ValueError('audit(): user_id, platform, api_key_id y operator no van juntos')
    if operator:
        actor = 'operator'
        details = dict(details or {}, operator_user_id=str(operator['user_id']),
                       operator_organization_id=str(operator['organization_id']))
    elif platform:
        actor = 'platform'
        details = dict(details or {}, platform_user_id=str(platform['user_id']))
    elif api_key_id:
        actor = 'api_key'
        details = dict(details or {}, api_key_id=str(api_key_id))
    else:
        actor = 'user' if user_id else 'system'
    conn.execute(
        'INSERT INTO audit_log (organization_id, actor_type, actor_user_id, action, entity_type, entity_id, ip_address, details) '
        'VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
        (org, actor, user_id, action, entity_type, entity_id, ip, psycopg.types.json.Jsonb(details or {})))

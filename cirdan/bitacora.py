"""Bitácora de la empresa y verificación de su cadena de hashes (#86, RC-130).

`audit_log` es de solo inserción y cada fila encadena su `row_hash` con el de la anterior de la misma empresa, con la
fórmula del trigger `audit_log_chain()` (migración 001). Aquí está el SQL que comparten la API
(cirdan/api/bitacora.py) y las pruebas (pruebas/test_bitacora.py). Va sin dependencias para que las pruebas del host
lo importen sin fastapi ni psycopg.

Las consultas filtran por `app_current_org()` además de RLS: con `cirdan_app` el filtro es el mismo que el de la
política, y como `postgres`, que salta RLS, sirven igual en la copia de la base de las pruebas.

Lo que la cadena sola no detecta: que alguien borre las últimas filas, porque las que quedan siguen cuadrando. Y la
cadena de la plataforma (`organization_id` NULL) no la ve ninguna empresa.
"""

# El row_hash que le toca a una fila de audit_log según su contenido: la fórmula del trigger audit_log_chain() de la
# 001 (también CADENA en pruebas/test_superadmin.py). Si el trigger cambia, esto cambia con él.
HASH_FILA = '''sha256(prev_hash || convert_to(concat_ws(chr(31),
           coalesce(organization_id::text, ''), chain_seq::text, id::text,
           (extract(epoch FROM occurred_at) * 1000000)::bigint::text,
           actor_type, coalesce(actor_user_id::text, ''), coalesce(actor_api_key_id::text, ''),
           action, coalesce(entity_type, ''), coalesce(entity_id::text, ''),
           details::text), 'UTF8'))'''

# Una fila con lo revisado y el primer eslabón roto, si hay. Cada fila se revisa en este orden:
#   chain_seq  la posición no es la que toca: falta una fila antes o se repite su número.
#   prev_hash  no apunta al row_hash de la fila anterior: se cambió la anterior y se recalculó su hash.
#   row_hash   no cuadra con su propio contenido: se cambió la fila.
VERIFICAR_SQL = '''
WITH cadena AS (
  SELECT id, chain_seq, prev_hash, row_hash,
         row_number() OVER w AS esperado_seq,
         coalesce(lag(row_hash) OVER w, decode(repeat('00', 32), 'hex')) AS esperado_prev,
         ''' + HASH_FILA + ''' AS esperado_hash
    FROM audit_log
   WHERE organization_id = app_current_org()
  WINDOW w AS (ORDER BY chain_seq)
), rotas AS (
  SELECT id, chain_seq,
         CASE WHEN chain_seq <> esperado_seq THEN 'chain_seq'
              WHEN prev_hash <> esperado_prev THEN 'prev_hash'
              WHEN row_hash <> esperado_hash THEN 'row_hash' END AS motivo
    FROM cadena
)
SELECT (SELECT count(*) FROM cadena) AS checked,
       (SELECT max(chain_seq) FROM cadena) AS last_chain_seq,
       r.id::text AS broken_id, r.chain_seq AS broken_seq, r.motivo AS broken_reason,
       clock_timestamp() AS verified_at
  FROM (SELECT 1) uno
  LEFT JOIN LATERAL (SELECT * FROM rotas WHERE motivo IS NOT NULL ORDER BY chain_seq LIMIT 1) r ON true
'''

# Las FK de la 001 son compuestas (empresa, id), así que los JOIN también: nunca se cruza con otra empresa.
LISTA_SQL = '''
SELECT a.id::text, a.chain_seq, a.occurred_at, a.actor_type, u.email::text AS user_email, k.name AS key_name,
       a.action, a.entity_type, a.entity_id::text, host(a.ip_address) AS ip_address, a.details
  FROM audit_log a
  LEFT JOIN users u ON u.organization_id = a.organization_id AND u.id = a.actor_user_id
  LEFT JOIN api_keys k ON k.organization_id = a.organization_id AND k.id = a.actor_api_key_id
 WHERE a.organization_id = app_current_org()
 ORDER BY a.chain_seq DESC
 LIMIT %s OFFSET %s
'''

TOTAL_SQL = 'SELECT count(*) AS total FROM audit_log WHERE organization_id = app_current_org()'

MOTIVOS = ('chain_seq', 'prev_hash', 'row_hash')


def actor(r):
    """Quién lo hizo, como texto (AuditEntry.actor del portal): el correo del usuario o el nombre de la llave.

    El superadmin en una empresa ajena ('platform') no lleva correo (RC-332): el portal lo muestra como superadmin de
    LowTide y su id está en details.platform_user_id. El sistema tampoco lleva actor."""
    if r['actor_type'] == 'user':
        return r['user_email']
    if r['actor_type'] == 'api_key':
        return r['key_name']
    return None


def fila(r):
    """Una fila de LISTA_SQL con la forma de AuditEntry del portal (FrontKL, src/types/api.ts), más chain_seq,
    entity_id e ip_address."""
    return {'id': r['id'], 'occurred_at': r['occurred_at'], 'actor_type': r['actor_type'], 'actor': actor(r),
            'action': r['action'], 'entity_type': r['entity_type'], 'details': r['details'],
            'chain_seq': r['chain_seq'], 'entity_id': r['entity_id'], 'ip_address': r['ip_address']}


def resultado(r):
    """La fila de VERIFICAR_SQL como respuesta de GET /api/v1/audit-log/verify."""
    roto = None
    if r['broken_id']:
        roto = {'id': r['broken_id'], 'chain_seq': r['broken_seq'], 'reason': r['broken_reason']}
    return {'status': 'broken' if roto else 'intact', 'checked': r['checked'],
            'last_chain_seq': r['last_chain_seq'], 'first_broken': roto, 'verified_at': r['verified_at']}

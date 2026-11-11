"""Llaves de API para integradores (#87, RC-129): crear, listar y revocar.

Solo el Administrador, y siempre con la sesión del portal: una llave no crea ni revoca llaves.
La llave completa sale una sola vez, en la respuesta de POST. Después solo se ve su prefijo.
Crear pide un plan con API (plans.api_and_siem). Listar y revocar no, para que una empresa que
bajó de plan todavía pueda revocar las que tenía.
"""
import uuid

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from cirdan.auth import api_keys, sessions
from cirdan.auth.deps import Session, client_ip, require_roles
from cirdan.db import audit, transaction

router = APIRouter(prefix='/api/v1/api-keys', tags=['llaves de API'])
admin = require_roles('admin')

DIAS_MAXIMO = 90      # igual que el CHECK de api_keys.expires_at
LLAVES_VIGENTES = 20  # por empresa, sin contar las revocadas ni las vencidas
SIN_PLAN = 'Tu plan no incluye la API. Está disponible en los planes Business y Enterprise.'
SIN_SESION = 'Tu sesión terminó. Vuelve a iniciar sesión.'
NO_ENCONTRADA = 'Llave no encontrada'


class LlaveIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    domain: str | None = Field(default=None, min_length=1, max_length=253)
    expires_in_days: int = Field(default=DIAS_MAXIMO, ge=1, le=DIAS_MAXIMO)


LISTA_SQL = '''
SELECT k.id::text, k.name, k.key_prefix, d.fqdn::text AS domain, k.scopes, u.email::text AS created_by,
       k.created_at, k.expires_at, k.last_used_at, k.revoked_at,
       CASE WHEN k.revoked_at IS NOT NULL THEN 'revoked' WHEN k.expires_at <= now() THEN 'expired'
            ELSE 'active' END AS status
  FROM api_keys k
  JOIN users u ON u.id = k.created_by
  LEFT JOIN domains d ON d.id = k.domain_id
'''


def _texto(valor, campo):
    valor = valor.strip()
    if not valor or any(ord(c) < 32 or ord(c) == 127 for c in valor):
        raise HTTPException(422, 'El campo %s no puede ir vacío ni llevar caracteres de control' % campo)
    return valor


@router.post('', status_code=201, summary='Crea una llave de API. La llave completa solo se muestra aquí (solo Admin)')
def create_api_key(body: LlaveIn, request: Request, response: Response, session: Session = Depends(admin)):
    nombre = _texto(body.name, 'name')
    fqdn = _texto(body.domain, 'domain') if body.domain is not None else None
    with transaction(session.org_id) as conn:
        # El rol de la sesión es el del día en que se inició. Una llave dura hasta 90 días, así que aquí
        # se vuelve a leer en la base: una cuenta desactivada o que ya no es Admin no deja una llave.
        if not conn.execute("SELECT 1 FROM users WHERE id = %s AND is_active AND role = 'admin'",
                            (session.user_id,)).fetchone():
            sessions.delete(session.token)
            raise HTTPException(401, SIN_SESION)
        # Candado sobre la empresa: dos altas a la vez no pasan del tope de llaves vigentes. NO KEY UPDATE
        # y no UPDATE, para no chocar con las FK hacia organizations (la de audit_log entre ellas).
        plan = conn.execute('SELECT p.api_and_siem FROM organizations o JOIN plans p ON p.id = o.plan_id '
                            'FOR NO KEY UPDATE OF o').fetchone()
        if not plan or not plan['api_and_siem']:
            raise HTTPException(403, SIN_PLAN)
        domain_id = None
        if fqdn is not None:
            dominio = conn.execute("SELECT id::text, fqdn::text FROM domains WHERE fqdn = %s AND status <> 'removed'",
                                   (fqdn,)).fetchone()
            if not dominio:
                raise HTTPException(404, 'Dominio no encontrado para esta organización')
            domain_id, fqdn = dominio['id'], dominio['fqdn']
        vigentes = conn.execute('SELECT count(*) AS n FROM api_keys WHERE revoked_at IS NULL AND expires_at > now()').fetchone()['n']
        if vigentes >= LLAVES_VIGENTES:
            raise HTTPException(409, 'Ya hay %d llaves vigentes. Revoca una antes de crear otra.' % LLAVES_VIGENTES)
        fila = None
        for _ in range(5):  # el prefijo visible es único y solo tiene 32 bits: si se repite, se genera otra
            llave, prefijo, huella = api_keys.generar()
            try:
                with conn.transaction():
                    fila = conn.execute(
                        'INSERT INTO api_keys (organization_id, domain_id, name, key_prefix, key_hash, scopes, created_by, expires_at) '
                        'VALUES (%s, %s, %s, %s, %s, %s, %s, now() + make_interval(days => %s)) '
                        'RETURNING id::text, created_at, expires_at',
                        (session.org_id, domain_id, nombre, prefijo, huella, [api_keys.LECTURA], session.user_id,
                         body.expires_in_days)).fetchone()
                break
            except psycopg.errors.UniqueViolation:
                continue
        if not fila:
            raise HTTPException(503, 'No se pudo generar la llave. Inténtalo de nuevo.')
        audit(conn, session.org_id, 'api_key.created', session.user_id, client_ip(request), 'api_key', fila['id'],
              {'name': nombre, 'key_prefix': prefijo, 'domain': fqdn, 'scopes': [api_keys.LECTURA],
               'expires_at': fila['expires_at'].isoformat()})
    response.headers['Cache-Control'] = 'no-store'
    return {'id': fila['id'], 'name': nombre, 'key_prefix': prefijo, 'domain': fqdn, 'scopes': [api_keys.LECTURA],
            'created_by': session.email, 'created_at': fila['created_at'], 'expires_at': fila['expires_at'],
            'last_used_at': None, 'revoked_at': None, 'status': 'active', 'key': llave}


@router.get('', summary='Llaves de API de la empresa, con su último uso. Nunca trae la llave (solo Admin)')
def list_api_keys(session: Session = Depends(admin)):
    with transaction(session.org_id) as conn:
        items = conn.execute(LISTA_SQL + ' ORDER BY k.created_at DESC, k.id').fetchall()
    return {'items': items, 'total': len(items)}


@router.delete('/{key_id}', status_code=204, summary='Revoca una llave de API. No se puede deshacer (solo Admin)')
def revoke_api_key(key_id: str, request: Request, session: Session = Depends(admin)):
    try:
        key_id = str(uuid.UUID(key_id))
    except ValueError:
        raise HTTPException(404, NO_ENCONTRADA)  # un id mal formado se responde igual que uno de otra empresa
    with transaction(session.org_id) as conn:
        fila = conn.execute('SELECT key_prefix, revoked_at FROM api_keys WHERE id = %s FOR UPDATE', (key_id,)).fetchone()
        if not fila:
            raise HTTPException(404, NO_ENCONTRADA)
        if fila['revoked_at'] is None:  # revocar dos veces no cambia la fecha ni repite la bitácora
            conn.execute('UPDATE api_keys SET revoked_at = now(), updated_at = now() WHERE id = %s', (key_id,))
            audit(conn, session.org_id, 'api_key.revoked', session.user_id, client_ip(request), 'api_key', key_id,
                  {'key_prefix': fila['key_prefix']})

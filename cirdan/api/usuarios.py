"""Usuarios de la empresa para su Admin (#141, RC-259): listar, cambiar el rol, dar de baja y revisar accesos.

Solo el Admin y siempre con la sesión del portal (una llave de API no administra cuentas). RLS deja ver solo la empresa
de la sesión: una cuenta de otra empresa responde 404, igual que una que no existe. Cada cambio queda en la bitácora con
quién lo hizo, a quién, qué cambió y el motivo. Las reglas están en cirdan/auth/cuentas.py.

La revisión de accesos (controles 5.16 y 5.18 de la política) es un evento `users.access_reviewed` en la bitácora con
la foto de las cuentas en ese momento y la nota del Admin. La política pide una cada mes y antes de cada entrega.
"""
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from cirdan.auth import cuentas
from cirdan.auth.deps import Session, client_ip, require_roles
from cirdan.db import audit, transaction

router = APIRouter(prefix='/api/v1/users', tags=['usuarios'])
admin = require_roles('admin')

NO_ENCONTRADO = 'Usuario no encontrado'
REVISION_CADA = timedelta(days=31)
SIN_USO_DIAS = 90
NOTA_MAXIMA = 1000

LISTA_SQL = '''
SELECT u.id::text, u.email::text, u.full_name, u.role, u.is_active, (u.mfa_enabled_at IS NOT NULL) AS mfa_enabled,
       u.last_login_at, u.created_at,
       (SELECT count(*) FROM api_keys k WHERE k.created_by = u.id AND k.revoked_at IS NULL AND k.expires_at > now())
         AS active_api_keys
  FROM users u
 ORDER BY u.is_active DESC, u.role, u.email
'''

REVISIONES_SQL = '''
SELECT a.occurred_at AS reviewed_at, u.email::text AS reviewed_by, a.details
  FROM audit_log a LEFT JOIN users u ON u.organization_id = a.organization_id AND u.id = a.actor_user_id
 WHERE a.action = 'users.access_reviewed'
 ORDER BY a.chain_seq DESC LIMIT %s
'''


def _ahora():
    return datetime.now(timezone.utc)


def _id(user_id):
    try:
        return str(uuid.UUID(user_id))
    except ValueError:
        raise HTTPException(404, NO_ENCONTRADO) from None   # mal formado se responde igual que de otra empresa


def _revisiones(conn, limite):
    filas = conn.execute(REVISIONES_SQL, (limite,)).fetchall()
    return [{'reviewed_at': f['reviewed_at'], 'reviewed_by': f['reviewed_by'], **(f['details'] or {})} for f in filas]


@router.get('', summary='Usuarios de la empresa con su rol, estado, MFA y último acceso (solo Admin)')
def list_users(session: Session = Depends(admin)):
    with transaction(session.org_id) as conn:
        items = conn.execute(LISTA_SQL).fetchall()
        ultima = _revisiones(conn, 1)
    ultima = ultima[0] if ultima else None
    return {'items': items, 'total': len(items), 'last_access_review': ultima,
            'access_review_due': ultima is None or ultima['reviewed_at'] + REVISION_CADA <= _ahora()}


@router.patch('/{user_id}', summary='Cambia el rol de un usuario o lo da de baja o de alta, con motivo (solo Admin)')
def update_user(user_id: str, request: Request, payload: dict[str, object] = Body(...),
                session: Session = Depends(admin)):
    user_id = _id(user_id)
    desconocidos = set(payload) - {'role', 'is_active', 'reason'}
    if desconocidos:
        raise HTTPException(422, 'Campos desconocidos: %s' % ', '.join(sorted(desconocidos)))
    revocadas = []
    with transaction(session.org_id) as conn:
        # Los Admin activos con candado: dos Admin no se quitan el rol el uno al otro a la vez y dejan la empresa sin
        # ninguno.
        admins = [f['id'] for f in conn.execute(
            "SELECT id::text FROM users WHERE role = 'admin' AND is_active ORDER BY id FOR UPDATE").fetchall()]
        objetivo = conn.execute('SELECT id::text, role, is_active FROM users WHERE id = %s FOR UPDATE',
                                (user_id,)).fetchone()
        if not objetivo:
            raise HTTPException(404, NO_ENCONTRADO)
        try:
            motivo = cuentas.motivo_valido(payload.get('reason'))
            cambio = cuentas.validar_cambio(session.user_id, objetivo, payload.get('role'), payload.get('is_active'),
                                            admins)
        except cuentas.CambioInvalido as error:
            raise HTTPException(error.codigo, str(error)) from error
        if cambio['role']:
            conn.execute('UPDATE users SET role = %s, updated_at = now() WHERE id = %s', (cambio['role'], user_id))
            audit(conn, session.org_id, 'user.role_changed', session.audit_user_id, client_ip(request), 'user',
                  user_id, {'from': objetivo['role'], 'to': cambio['role'], 'reason': motivo},
                  platform=session.audit_platform)
        if cambio['is_active'] is False:
            revocadas = cuentas.desactivar(conn, user_id)
            audit(conn, session.org_id, 'user.deactivated', session.audit_user_id, client_ip(request), 'user',
                  user_id, {'reason': motivo, 'revoked_api_keys': revocadas}, platform=session.audit_platform)
        elif cambio['is_active'] is True:
            conn.execute('UPDATE users SET is_active = true, updated_at = now() WHERE id = %s', (user_id,))
            audit(conn, session.org_id, 'user.reactivated', session.audit_user_id, client_ip(request), 'user',
                  user_id, {'reason': motivo}, platform=session.audit_platform)
        fila = conn.execute(LISTA_SQL.replace(' ORDER BY', ' WHERE u.id = %s ORDER BY'), (user_id,)).fetchone()
    # Después del commit: el rol vive en la sesión de Valkey, así que un cambio de rol o una baja cierran las sesiones
    # abiertas y aplican al momento (RC-282 hará que cada petición lea el rol de la base).
    if cambio['role'] or cambio['is_active'] is False:
        cuentas.cerrar_sesiones(user_id)
    return {**fila, 'changed': bool(cambio['role'] or cambio['is_active'] is not None), 'revoked_api_keys': revocadas,
            'sessions_closed': bool(cambio['role'] or cambio['is_active'] is False)}


@router.post('/access-review', status_code=201,
             summary='Registra la revisión de accesos de la empresa con su nota (solo Admin)')
def access_review(request: Request, payload: dict[str, object] = Body(default={}),
                  session: Session = Depends(admin)):
    nota = payload.get('notes')
    if nota is not None and (not isinstance(nota, str) or len(nota) > NOTA_MAXIMA):
        raise HTTPException(422, 'notes debe ser texto de hasta %d caracteres.' % NOTA_MAXIMA)
    with transaction(session.org_id) as conn:
        cuentas_hoy = conn.execute(LISTA_SQL).fetchall()
        activas = [c for c in cuentas_hoy if c['is_active']]
        limite = _ahora() - timedelta(days=SIN_USO_DIAS)
        foto = {
            'users': len(cuentas_hoy),
            'active': len(activas),
            'admins': sum(1 for c in activas if c['role'] == 'admin'),
            'without_mfa': sum(1 for c in activas if not c['mfa_enabled']),
            'unused_%dd' % SIN_USO_DIAS: sum(1 for c in activas if not c['last_login_at'] or c['last_login_at'] < limite),
            'notes': ' '.join(nota.split()) if isinstance(nota, str) and nota.strip() else None,
        }
        audit(conn, session.org_id, 'users.access_reviewed', session.audit_user_id, client_ip(request), None, None,
              foto, platform=session.audit_platform)
        revision = _revisiones(conn, 1)[0]
    return {**revision, 'next_due': revision['reviewed_at'] + REVISION_CADA}


@router.get('/access-reviews', summary='Revisiones de accesos registradas, de la más nueva a la más vieja (solo Admin)')
def access_reviews(session: Session = Depends(admin)):
    with transaction(session.org_id) as conn:
        items = _revisiones(conn, 24)
    return {'items': items, 'total': len(items),
            'next_due': items[0]['reviewed_at'] + REVISION_CADA if items else None}

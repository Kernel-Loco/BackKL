"""Endpoints de inicio de sesión: /api/v1/auth/login, /mfa/verify, /logout, /me y /password.

Los errores de credenciales usan siempre el mismo mensaje y el mismo tiempo, exista o no el
correo, para que nadie pueda saber qué cuentas existen.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from cirdan.auth import passwords, sessions, totp
from cirdan.auth.deps import COOKIE, COOKIE_SECURE, Session, client_ip, current_session
from cirdan.db import audit, transaction

router = APIRouter(prefix='/api/v1/auth', tags=['sesión'])
log = logging.getLogger(__name__)

INVALID = 'Correo o contraseña incorrectos.'
LOCKED = 'Demasiados intentos. Espera 15 minutos e inténtalo de nuevo.'
MFA_EXPIRED = 'Tu verificación expiró. Inicia sesión de nuevo.'
MFA_INVALID = 'El código no es válido o ya expiró.'


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=passwords.MAX_LENGTH)


class MfaIn(BaseModel):
    mfa_token: str = Field(min_length=10, max_length=100)
    code: str = Field(pattern=r'^\d{6}$')


class PasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=passwords.MAX_LENGTH)
    new_password: str = Field(min_length=passwords.MIN_LENGTH, max_length=passwords.MAX_LENGTH)


USER_SQL = '''
SELECT u.id::text, u.email::text, u.full_name, u.role, u.organization_id::text, o.name AS organization_name,
       u.mfa_enabled_at IS NOT NULL AND u.totp_secret_enc IS NOT NULL AS mfa_enabled, u.last_login_at
  FROM users u JOIN organizations o ON o.id = u.organization_id
 WHERE u.id = %s AND u.is_active
'''


def _user(conn, user_id):
    return conn.execute(USER_SQL, (user_id,)).fetchone()


def _start_session(response, conn, user, ip, via):
    """Crea la sesión, pone la cookie y lo deja en la bitácora."""
    conn.execute('UPDATE users SET last_login_at = now() WHERE id = %s', (user['id'],))
    audit(conn, user['organization_id'], 'auth.login_succeeded', user['id'], ip, 'user', user['id'], {'via': via})
    token = sessions.create({'user_id': user['id'], 'org_id': user['organization_id'], 'role': user['role'], 'email': user['email']})
    response.set_cookie(COOKIE, token, httponly=True, secure=COOKIE_SECURE, samesite='lax', path='/')
    return _user(conn, user['id'])


def _audit_bad_password(org, user_id, ip):
    # Corre después del 401. Si falla, queda solo en el log: una excepción aquí haría que uvicorn
    # cerrara la conexión, y eso solo pasaría con correos que existen.
    try:
        with transaction(org) as conn:
            audit(conn, org, 'auth.login_failed', user_id, ip, 'user', user_id, {'reason': 'password'})
    except Exception:
        log.exception('No se pudo escribir auth.login_failed del usuario %s', user_id)


@router.post('/login',summary='Correo y contraseña; si la cuenta tiene MFA, pide el código')
def login(body: LoginIn, request: Request, response: Response):
    email = body.email.strip().lower()
    ip = client_ip(request)
    if sessions.is_locked(email, ip):
        raise HTTPException(429, LOCKED, headers={'Retry-After': str(sessions.LOCK_SECONDS)})

    with transaction() as conn:
        found = conn.execute('SELECT * FROM login_lookup(%s)', (email,)).fetchone()
    if not found:
        passwords.burn_time(body.password)
        sessions.register_fail(email, ip)
        raise HTTPException(401, INVALID)

    org, user_id = str(found['organization_id']), str(found['user_id'])
    if not passwords.verify_password(found['password_hash'], body.password):
        sessions.register_fail(email, ip)
        # La bitácora se escribe después de mandar el 401. Escrita antes, la conexión y el INSERT
        # hacían que un correo que existe tardara unos 17 ms más que uno que no existe.
        # Con raise HTTPException la tarea no correría: por eso se devuelve el mismo 401 a mano.
        return JSONResponse({'detail': INVALID}, status_code=401,
                            background=BackgroundTask(_audit_bad_password, org, user_id, ip))

    sessions.clear_fails(email)
    with transaction(org) as conn:
        if passwords.needs_rehash(found['password_hash']):
            conn.execute('UPDATE users SET password_hash = %s WHERE id = %s', (passwords.hash_password(body.password), user_id))
        if found['mfa_enabled']:
            return {'mfa_required': True, 'mfa_token': sessions.create_mfa({'user_id': user_id, 'org_id': org})}
        # login_lookup() no devuelve el rol (migración 004): se lee aquí con RLS, como en /mfa/verify
        row = conn.execute('SELECT role FROM users WHERE id = %s AND is_active', (user_id,)).fetchone()
        if not row:  # se desactivó la cuenta entre la búsqueda y aquí
            raise HTTPException(401, INVALID)
        user = _start_session(response, conn, {'id': user_id, 'organization_id': org, 'role': row['role'], 'email': email}, ip, 'password')
    return {'mfa_required': False, 'user': user}


@router.post('/mfa/verify', summary='Segundo paso: código de 6 dígitos de la app autenticadora')
def verify_mfa(body: MfaIn, request: Request, response: Response):
    pending = sessions.get_mfa(body.mfa_token)
    if not pending:
        raise HTTPException(401, MFA_EXPIRED)
    ip = client_ip(request)
    org, user_id = pending['org_id'], pending['user_id']
    with transaction(org) as conn:
        row = conn.execute(
            'SELECT email::text, role, totp_secret_enc, last_totp_step FROM users WHERE id = %s AND is_active', (user_id,)).fetchone()
        if not row or not row['totp_secret_enc']:
            sessions.delete_mfa(body.mfa_token)
            raise HTTPException(401, MFA_EXPIRED)
        step = totp.verify_code(totp.decrypt_secret(row['totp_secret_enc'], user_id), body.code, row['last_totp_step'])
        if step is None:
            audit(conn, org, 'auth.mfa_failed', user_id, ip, 'user', user_id)
            fail = True
        else:
            fail = False
            conn.execute('UPDATE users SET last_totp_step = %s WHERE id = %s', (step, user_id))
            sessions.delete_mfa(body.mfa_token)
            user = _start_session(response, conn, {'id': user_id, 'organization_id': org, 'role': row['role'], 'email': row['email']}, ip, 'totp')
    if fail:
        sessions.fail_mfa(body.mfa_token, pending)
        raise HTTPException(401, MFA_INVALID)
    return {'user': user}


@router.post('/logout', status_code=204, summary='Cierra la sesión y la borra del servidor')
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    data = sessions.get(token)
    if data:
        with transaction(data['org_id']) as conn:
            audit(conn, data['org_id'], 'auth.logout', data['user_id'], client_ip(request), 'user', data['user_id'])
    sessions.delete(token)
    response.delete_cookie(COOKIE, path='/', httponly=True, secure=COOKIE_SECURE, samesite='lax')


@router.get('/me', summary='Usuario de la sesión')
def me(session: Session = Depends(current_session)):
    with transaction(session.org_id) as conn:
        user = _user(conn, session.user_id)
    if not user:  # se desactivó la cuenta con la sesión abierta
        sessions.delete(session.token)
        raise HTTPException(401, 'Tu sesión terminó. Vuelve a iniciar sesión.')
    return user


@router.post('/password', status_code=204, summary='Cambia la contraseña del usuario de la sesión')
def change_password(body: PasswordIn, request: Request, session: Session = Depends(current_session)):
    with transaction(session.org_id) as conn:
        row = conn.execute('SELECT password_hash FROM users WHERE id = %s', (session.user_id,)).fetchone()
        if not row or not passwords.verify_password(row['password_hash'], body.current_password):
            raise HTTPException(400, 'La contraseña actual no es correcta.')
        conn.execute('UPDATE users SET password_hash = %s, updated_at = now() WHERE id = %s',
                     (passwords.hash_password(body.new_password), session.user_id))
        audit(conn, session.org_id, 'auth.password_changed', session.user_id, client_ip(request), 'user', session.user_id)

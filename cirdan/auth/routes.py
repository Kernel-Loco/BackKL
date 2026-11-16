"""Endpoints de inicio de sesión: /api/v1/auth/captcha, /login, /mfa/verify, /mfa/setup, /mfa/enable, /logout, /me y /password.

Los errores de credenciales usan siempre el mismo mensaje y el mismo tiempo, exista o no el
correo, para que nadie pueda saber qué cuentas existen.
"""
import base64
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from cirdan.auth import captcha, passwords, sessions, totp
from cirdan.auth.deps import COOKIE, COOKIE_SECURE, Session, client_ip, current_session
from cirdan.db import audit, transaction

router = APIRouter(prefix='/api/v1/auth', tags=['sesión'])
log = logging.getLogger(__name__)

INVALID = 'Correo o contraseña incorrectos.'
LOCKED = 'Demasiados intentos. Espera 15 minutos e inténtalo de nuevo.'
MFA_EXPIRED = 'Tu verificación expiró. Inicia sesión de nuevo.'
MFA_INVALID = 'El código no es válido o ya expiró.'
CAPTCHA_INVALID = 'No se pudo comprobar que no eres un robot. Espera a que termine la verificación e inténtalo de nuevo.'


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=passwords.MAX_LENGTH)
    # Opcional en el modelo para que, si falta, el portal reciba CAPTCHA_INVALID y no un 422 sin explicación.
    captcha: str | None = Field(default=None, max_length=captcha.MAX_PAYLOAD)


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
    return dict(_user(conn, user['id']), **sessions.limits())


def _clear_fails(email):
    # Corre cuando la sesión ya se creó. Si Valkey falla aquí, el contador vence solo en 15 min:
    # un 500 dejaría al usuario sin cookie con la sesión creada y el código ya gastado.
    try:
        sessions.clear_fails(email)
    except Exception:
        log.exception('No se pudieron borrar los fallos del correo después de iniciar sesión')


def _audit_bad_password(org, user_id, ip):
    # Corre después del 401. Si falla, queda solo en el log: una excepción aquí haría que uvicorn
    # cerrara la conexión, y eso solo pasaría con correos que existen.
    try:
        with transaction(org) as conn:
            audit(conn, org, 'auth.login_failed', user_id, ip, 'user', user_id, {'reason': 'password'})
    except Exception:
        log.exception('No se pudo escribir auth.login_failed del usuario %s', user_id)


@router.get('/captcha', summary='Reto del captcha (prueba de trabajo ALTCHA) para el siguiente inicio de sesión')
def get_captcha(response: Response):
    response.headers.update(NO_STORE)
    return captcha.new_challenge()


@router.post('/login',summary='Correo, contraseña y captcha; si la cuenta tiene MFA, pide el código')
def login(body: LoginIn, request: Request, response: Response):
    # El captcha va antes que todo: sin él no se busca el correo ni se mira el bloqueo, así que la respuesta no dice
    # nada de la cuenta. No cuenta como fallo de contraseña: si contara, cualquiera bloquearía un correo ajeno sin
    # hacer la prueba de trabajo. Se gasta aunque después falle la contraseña.
    if not captcha.verify(body.captcha):
        raise HTTPException(400, CAPTCHA_INVALID)
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
    if not passwords.verify_password(found['password_hash'], body.password, user_id):
        sessions.register_fail(email, ip)
        # La bitácora se escribe después de mandar el 401. Escrita antes, la conexión y el INSERT
        # hacían que un correo que existe tardara unos 17 ms más que uno que no existe.
        # Con raise HTTPException la tarea no correría: por eso se devuelve el mismo 401 a mano.
        return JSONResponse({'detail': INVALID}, status_code=401,
                            background=BackgroundTask(_audit_bad_password, org, user_id, ip))

    with transaction(org) as conn:
        if passwords.needs_rehash(found['password_hash'], user_id):
            # Una huella vieja sin cifrar queda cifrada en este mismo inicio de sesión (RC-330). Solo si nadie la
            # cambió desde la búsqueda: así un cambio de contraseña en paralelo no se pisa con la anterior.
            # Sin fila cambiada, otra petición guardó una huella nueva mientras tanto: la de un login en paralelo de
            # la misma cuenta (doble clic), que la cifró con esta misma contraseña, o la de un cambio de contraseña.
            # Se relee y solo entra si la contraseña también abre la huella que quedó.
            if not conn.execute('UPDATE users SET password_hash = %s WHERE id = %s AND password_hash = %s',
                                (passwords.hash_password(body.password, user_id), user_id,
                                 found['password_hash'])).rowcount:
                actual = conn.execute('SELECT password_hash FROM users WHERE id = %s', (user_id,)).fetchone()
                if not actual or not passwords.verify_password(actual['password_hash'], body.password, user_id):
                    raise HTTPException(401, INVALID)
        if found['mfa_enabled']:
            # Los fallos del correo se borran hasta que el código sea correcto. Borrados aquí, quien
            # tiene la contraseña repetiría el login y 5 códigos sin llegar nunca al bloqueo.
            return {'mfa_required': True, 'mfa_token': sessions.create_mfa({'user_id': user_id, 'org_id': org, 'email': email})}
        # login_lookup() no devuelve el rol (migración 004): se lee aquí con RLS, como en /mfa/verify.
        # FOR NO KEY UPDATE (RC-154), como el UPDATE de last_login_at que viene: un alta de TOTP a la vez espera
        # a que esta sesión entre al índice y la cierra, o esta lectura espera al alta y la ve ya activa. Con FOR
        # SHARE dos logins a la vez de la misma cuenta chocaban en un deadlock al subir al lock del UPDATE.
        row = conn.execute('SELECT role, %s AS mfa_enabled FROM users WHERE id = %%s AND is_active FOR NO KEY UPDATE'
                           % MFA_ENABLED_SQL, (user_id,)).fetchone()
        if not row:  # se desactivó la cuenta entre la búsqueda y aquí
            raise HTTPException(401, INVALID)
        if row['mfa_enabled']:  # se activó entre la búsqueda y aquí
            return {'mfa_required': True, 'mfa_token': sessions.create_mfa({'user_id': user_id, 'org_id': org, 'email': email})}
        user = _start_session(response, conn, {'id': user_id, 'organization_id': org, 'role': row['role'], 'email': email}, ip, 'password')
    _clear_fails(email)
    return {'mfa_required': False, 'user': user}


@router.post('/mfa/verify', summary='Segundo paso: código de 6 dígitos de la app autenticadora')
def verify_mfa(body: MfaIn, request: Request, response: Response):
    # El intento se gasta antes de revisar el código, en el mfa_token y en el correo, para que ni
    # las peticiones en paralelo ni volver a iniciar sesión den más de 5 códigos.
    pending = sessions.take_mfa(body.mfa_token)
    if pending and 'email' not in pending:  # token creado antes de este cambio
        sessions.delete_mfa(body.mfa_token)
        pending = None
    if not pending:
        raise HTTPException(401, MFA_EXPIRED)
    ip = client_ip(request)
    org, user_id, email = pending['org_id'], pending['user_id'], pending['email']
    if not sessions.take_mfa_attempt(email, ip):
        raise HTTPException(429, LOCKED, headers={'Retry-After': str(sessions.LOCK_SECONDS)})
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
        sessions.register_mfa_fail(ip)
        raise HTTPException(401, MFA_INVALID)
    _clear_fails(email)
    return {'user': user}


MFA_ALREADY = 'La verificación en dos pasos ya está activa en tu cuenta.'
MFA_SETUP_EXPIRED = 'El código QR venció o ya se usaron sus 5 intentos. Empieza de nuevo.'
WRONG_PASSWORD = 'La contraseña actual no es correcta.'
SESSION_ENDED = 'Tu sesión terminó. Vuelve a iniciar sesión.'
NO_STORE = {'Cache-Control': 'no-store'}
MFA_ENABLED_SQL = 'mfa_enabled_at IS NOT NULL AND totp_secret_enc IS NOT NULL'


class MfaSetupIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=passwords.MAX_LENGTH)


class MfaEnableIn(BaseModel):
    code: str = Field(pattern=r'^\d{6}$')


@router.post('/mfa/setup', summary='Alta de TOTP, paso 1: con la contraseña, un secreto nuevo con su QR')
def mfa_setup(body: MfaSetupIn, request: Request, response: Response, session: Session = Depends(current_session)):
    # Pide la contraseña para que una cookie robada no baste para atar la cuenta a la app de otra persona.
    # Una contraseña equivocada cuenta para el bloqueo del login, igual que en /login.
    ip = client_ip(request)
    if sessions.is_locked(session.email, ip):
        raise HTTPException(429, LOCKED, headers={'Retry-After': str(sessions.LOCK_SECONDS)})
    with transaction(session.org_id) as conn:
        row = conn.execute('SELECT email::text, password_hash, %s AS mfa_enabled FROM users WHERE id = %%s AND is_active'
                           % MFA_ENABLED_SQL, (session.user_id,)).fetchone()
        if not row:
            sessions.delete(session.token)
            raise HTTPException(401, SESSION_ENDED)
        bad_password = not passwords.verify_password(row['password_hash'], body.current_password, session.user_id)
        if bad_password:
            audit(conn, session.org_id, 'auth.mfa_setup_failed', session.user_id, ip, 'user', session.user_id,
                  {'reason': 'password'})
        elif row['mfa_enabled']:
            raise HTTPException(409, MFA_ALREADY)
        else:
            audit(conn, session.org_id, 'auth.mfa_setup_started', session.user_id, ip, 'user', session.user_id)
    if bad_password:
        sessions.register_fail(session.email, ip)
        raise HTTPException(400, WRONG_PASSWORD)
    secret = totp.new_secret()
    # En Valkey va cifrado con la misma llave y el mismo dato asociado que en la base: quien lea Valkey no lo puede usar.
    sessions.create_mfa_setup(session.user_id, base64.b64encode(totp.encrypt_secret(secret, session.user_id)).decode())
    uri = totp.provisioning_uri(secret, row['email'])
    response.headers.update(NO_STORE)
    return {'otpauth_uri': uri, 'secret': secret, 'qr_svg': totp.qr_svg_data_uri(uri),
            'expires_in_seconds': sessions.MFA_SETUP_SECONDS}


@router.post('/mfa/enable', summary='Alta de TOTP, paso 2: guarda el secreto solo si el código de la app es válido')
def mfa_enable(body: MfaEnableIn, request: Request, session: Session = Depends(current_session)):
    # El intento se gasta antes de revisar el código, como en /mfa/verify: en paralelo tampoco pasan de 5.
    pending = sessions.take_mfa_setup(session.user_id)
    if not pending:
        raise HTTPException(400, MFA_SETUP_EXPIRED)
    ip = client_ip(request)
    secret = totp.decrypt_secret(base64.b64decode(pending['secret_enc']), session.user_id)
    with transaction(session.org_id) as conn:
        # FOR UPDATE: dos códigos válidos a la vez no guardan dos secretos; el segundo ve la cuenta ya activa.
        row = conn.execute('SELECT %s AS mfa_enabled FROM users WHERE id = %%s AND is_active FOR UPDATE' % MFA_ENABLED_SQL,
                           (session.user_id,)).fetchone()
        if not row:
            sessions.delete_mfa_setup(session.user_id)
            sessions.delete(session.token)
            raise HTTPException(401, SESSION_ENDED)
        if row['mfa_enabled']:
            sessions.delete_mfa_setup(session.user_id)
            raise HTTPException(409, MFA_ALREADY)
        step = totp.verify_code(secret, body.code)
        if step is None:
            audit(conn, session.org_id, 'auth.mfa_enable_failed', session.user_id, ip, 'user', session.user_id)
        else:
            # last_totp_step con el paso de este código: el mismo código no sirve después para iniciar sesión.
            conn.execute('UPDATE users SET totp_secret_enc = %s, mfa_enabled_at = now(), last_totp_step = %s, '
                         'updated_at = now() WHERE id = %s',
                         (totp.encrypt_secret(secret, session.user_id), step, session.user_id))
            audit(conn, session.org_id, 'auth.mfa_enabled', session.user_id, ip, 'user', session.user_id)
            # Las demás sesiones de la cuenta entraron sin el segundo factor: se cierran y solo queda la que activó.
            # Va antes del commit y con la fila bloqueada: si Valkey falla, el alta no se guarda y se puede repetir.
            sessions.delete_others(session.user_id, session.token)
    if step is None:
        sessions.register_mfa_fail(ip)
        raise HTTPException(400, MFA_INVALID)
    sessions.delete_mfa_setup(session.user_id)
    return {'mfa_enabled': True}


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
    return dict(user, **sessions.limits(session.created_at))


@router.post('/password', status_code=204, summary='Cambia la contraseña del usuario de la sesión')
def change_password(body: PasswordIn, request: Request, session: Session = Depends(current_session)):
    with transaction(session.org_id) as conn:
        row = conn.execute('SELECT password_hash FROM users WHERE id = %s', (session.user_id,)).fetchone()
        if not row or not passwords.verify_password(row['password_hash'], body.current_password, session.user_id):
            raise HTTPException(400, 'La contraseña actual no es correcta.')
        conn.execute('UPDATE users SET password_hash = %s, updated_at = now() WHERE id = %s',
                     (passwords.hash_password(body.new_password, session.user_id), session.user_id))
        audit(conn, session.org_id, 'auth.password_changed', session.user_id, client_ip(request), 'user', session.user_id)

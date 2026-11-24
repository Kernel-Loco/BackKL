"""Endpoints de inicio de sesión: /api/v1/auth/captcha, /login, /mfa/verify, /mfa/setup, /mfa/enable, /logout, /me,
/password, las passkeys (/passkeys, RC-331), el enlace al correo (/link/request y /link/verify, #28, RC-63) y la
recuperación de la contraseña con un enlace (/password-reset y /password-reset/confirm, RC-335).

Los errores de credenciales usan siempre el mismo mensaje y el mismo tiempo, exista o no el
correo, para que nadie pueda saber qué cuentas existen.
"""
import base64
import logging
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
import psycopg
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from cirdan import correo
from cirdan.auth import captcha, passwords, sessions, totp, webauthn
from cirdan.auth.deps import COOKIE, COOKIE_SECURE, Session, client_ip, current_session, is_platform_admin
from cirdan.auth.demo import HASH_DE_RELLENO
from cirdan.config import config, origenes_permitidos
from cirdan.db import audit, transaction

router = APIRouter(prefix='/api/v1/auth', tags=['sesión'])
log = logging.getLogger(__name__)

INVALID = 'Correo o contraseña incorrectos.'
LOCKED = 'Demasiados intentos. Espera 15 minutos e inténtalo de nuevo.'
MFA_EXPIRED = 'Tu verificación expiró. Inicia sesión de nuevo.'
MFA_INVALID = 'El código no es válido o ya expiró.'
OPERATOR_MFA_REQUIRED = 'Las cuentas de operador deben tener MFA activo antes de iniciar sesión.'
CAPTCHA_INVALID = 'No se pudo comprobar que no eres un robot. Espera a que termine la verificación e inténtalo de nuevo.'


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=passwords.MAX_LENGTH)
    # Opcional en el modelo para que, si falta, el portal reciba CAPTCHA_INVALID y no un 422 sin explicación.
    captcha: str | None = Field(default=None, max_length=captcha.MAX_PAYLOAD)


class MfaIn(BaseModel):
    mfa_token: str = Field(min_length=10, max_length=100)
    code: str = Field(pattern=totp.CODE_PATTERN)


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


def platform_view(session, user):
    """Lo que /me agrega para el superadmin (RC-332). `user` es la fila de USER_SQL, leída con la empresa de la cuenta.
    En una empresa ajena, organization_id y organization_name son los de la empresa activa y role el de la sesión.
    platform_admin pide la bandera de la sesión y también la base: si se le quitó el permiso o el TOTP con la sesión
    en su empresa, el portal deja de mostrar el selector. Un permiso nuevo sigue pidiendo volver a iniciar sesión."""
    admin = session.platform_admin and is_platform_admin(session.user_id)
    out = {'platform_admin': admin}
    if admin:
        out.update(home_organization_id=user['organization_id'], home_organization_name=user['organization_name'])
    if session.acting_elsewhere:
        with transaction(session.org_id) as conn:
            org = conn.execute('SELECT id::text, name FROM organizations').fetchone()
        if not org:
            sessions.delete(session.token)
            raise HTTPException(401, SESSION_ENDED)
        out.update(organization_id=org['id'], organization_name=org['name'], role=session.role)
    return out


def _start_session(response, conn, user, ip, via):
    """Crea la sesión, pone la cookie y lo deja en la bitácora. Siempre empieza en la empresa de la cuenta."""
    conn.execute('UPDATE users SET last_login_at = now() WHERE id = %s', (user['id'],))
    audit(conn, user['organization_id'], 'auth.login_succeeded', user['id'], ip, 'user', user['id'], {'via': via})
    platform = bool(conn.execute('SELECT public.is_platform_admin(%s) AS ok', (user['id'],)).fetchone()['ok'])
    token = sessions.create({'user_id': user['id'], 'org_id': user['organization_id'], 'role': user['role'],
                             'email': user['email'], 'home_org_id': user['organization_id'], 'platform_admin': platform})
    response.set_cookie(COOKIE, token, httponly=True, secure=COOKIE_SECURE, samesite='lax', path='/')
    row = _user(conn, user['id'])
    session = Session(token=token, user_id=user['id'], org_id=user['organization_id'], role=user['role'],
                      email=user['email'], home_org_id=user['organization_id'], platform_admin=platform)
    return dict(row, **platform_view(session, row), **sessions.limits())


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


def _bad_password(org, user_id, ip):
    return JSONResponse({'detail': INVALID}, status_code=401,
                        background=BackgroundTask(_audit_bad_password, org, user_id, ip))


# Etiquetas de letras, números y guiones separadas por puntos, con la última (el TLD) empezando con letra.
_DOMINIO = re.compile(r'(?:[a-z0-9-]{1,63}\.)+[a-z][a-z0-9-]{1,62}')
NO_ES_DOMINIO = 'no-es-dominio'


def _email_domain(email):
    """Del correo que no existe solo queda el dominio, nunca el correo completo (RC-302, decisión 2b de Ernesto). Si lo
    que sigue a la última '@' no tiene forma de dominio, queda un marcador fijo: alguien que escribe la contraseña en
    el campo del correo ('Clave@Marzo2026' o 'juan@empresa.com MiClave') no deja un pedazo de ella en el log."""
    dominio = email.rpartition('@')[2].lower()
    if '@' in email and len(dominio) <= 253 and _DOMINIO.fullmatch(dominio):
        return dominio
    return NO_ES_DOMINIO


def _log_unknown_email(email, ip):
    # Sin empresa no cabe en audit_log (su RLS pide organization_id = app_current_org()): va al log de la API (RC-302,
    # decisión 1a). Corre después del 401, como _audit_bad_password con el correo que existe. %r escapa los saltos de
    # línea, así que un correo o una IP con '\n' no inventan otra línea del log.
    log.warning('auth.login_failed de un correo que no existe: ip=%r dominio=%r', ip, _email_domain(email))


def _locked(task):
    # El mismo 429 de siempre con una tarea después de la respuesta. Con raise HTTPException la tarea no correría.
    return JSONResponse({'detail': LOCKED}, status_code=429, headers={'Retry-After': str(sessions.LOCK_SECONDS)},
                        background=task)


def _lock_kinds(por_correo, por_ip):
    return [kind for kind, nuevo in (('email', por_correo), ('ip', por_ip)) if nuevo]


def _record_login_locked(email, ip):
    """El 429 de /login, en la bitácora de la empresa si el correo existe o en el log de la API si no (RC-302). Corre
    después de la respuesta: el 429 sale antes de buscar el correo y así sigue, igual de rápido exista o no.
    Solo el primero de cada ventana de bloqueo, por correo y por IP, porque audit_log no se purga."""
    try:
        por_correo, por_ip = sessions.first_lock('login', email, ip)
    except Exception:
        log.exception('No se pudo revisar en Valkey si el 429 del inicio de sesión ya tenía aviso')
        return
    if not (por_correo or por_ip):
        return
    lock = _lock_kinds(por_correo, por_ip)
    try:
        with transaction() as conn:
            found = conn.execute('SELECT user_id, organization_id FROM login_lookup(%s)', (email,)).fetchone()
        if not found:
            log.warning('auth.login_locked de un correo que no existe: ip=%r dominio=%r bloqueo=%s',
                        ip, _email_domain(email), '+'.join(lock))
            return
        org, user_id = str(found['organization_id']), str(found['user_id'])
        with transaction(org) as conn:
            audit(conn, org, 'auth.login_locked', user_id, ip, 'user', user_id, {'lock': lock})
    except Exception:
        log.exception('No se pudo escribir auth.login_locked')
        _forget_lock_quietly('login', email, ip, por_correo, por_ip)


def _record_mfa_locked(org, user_id, email, ip):
    """El 429 de /mfa/verify en la bitácora de la empresa (RC-302). Solo el primero de cada ventana de bloqueo, por
    correo y, para la IP, por empresa: con una IP bloqueada, el 429 de otra empresa también deja su evento."""
    try:
        por_correo, por_ip = sessions.first_lock('mfa', email, ip, org)
    except Exception:
        log.exception('No se pudo revisar en Valkey si el 429 del código del usuario %s ya tenía aviso', user_id)
        return
    if not (por_correo or por_ip):
        return
    try:
        with transaction(org) as conn:
            audit(conn, org, 'auth.mfa_locked', user_id, ip, 'user', user_id, {'lock': _lock_kinds(por_correo, por_ip)})
    except Exception:
        log.exception('No se pudo escribir auth.mfa_locked del usuario %s', user_id)
        _forget_lock_quietly('mfa', email, ip, por_correo, por_ip, org)


def _forget_lock_quietly(event, email, ip, por_correo, por_ip, org=None):
    try:
        sessions.forget_lock(event, email, ip, por_correo, por_ip, org)
    except Exception:
        log.exception('No se pudo quitar la marca del aviso de bloqueo después de un error')


def _refund_quietly(email, ip, ticket):
    # Si Valkey también falla, sale la excepción original y el intento vence solo en 15 min.
    try:
        sessions.refund_login_attempt(email, ip, ticket)
    except Exception:
        log.exception('No se pudo devolver el intento de inicio de sesión después de un error')


@router.get('/captcha', summary='Reto del captcha (prueba de trabajo ALTCHA) para el siguiente inicio de sesión')
def get_captcha(response: Response):
    response.headers.update(NO_STORE)
    return captcha.new_challenge()


@router.post('/login', summary='Correo, contraseña y captcha; pide MFA cuando la cuenta lo requiere')
def login(body: LoginIn, request: Request, response: Response):
    # El captcha va antes que todo: sin él no se busca el correo ni se mira el bloqueo, así que la respuesta no dice
    # nada de la cuenta. No cuenta como fallo de contraseña: si contara, cualquiera bloquearía un correo ajeno sin
    # hacer la prueba de trabajo. Se gasta aunque después falle la contraseña.
    if not captcha.verify(body.captcha):
        raise HTTPException(400, CAPTCHA_INVALID)
    email = body.email.strip().lower()
    ip = client_ip(request)
    # El intento cuenta como fallo del correo y de la IP antes de buscar la cuenta, en un solo paso de Valkey (RC-270).
    # Revisado y contado por separado, 30 contraseñas a la vez leían todas el contador en 0 y se revisaban todas.
    # Va antes de buscar el correo, así que el 429 sale igual exista o no la cuenta.
    ticket = sessions.take_login_attempt(email, ip)
    if not ticket:
        # Quién era la cuenta se busca después de mandar el 429 (RC-302).
        return _locked(BackgroundTask(_record_login_locked, email, ip))

    try:
        with transaction() as conn:
            found = conn.execute('SELECT * FROM login_lookup(%s)', (email,)).fetchone()
        if found:
            good = passwords.verify_password(found['password_hash'], body.password, str(found['user_id']))
        else:
            passwords.burn_time(body.password)
    except Exception:
        # La base o la huella fallaron y la contraseña no se llegó a revisar: el 500 no es un fallo y no cuenta. El
        # relleno del correo que no existe va en el mismo try: si su error contara, el contador diría qué correos existen.
        _refund_quietly(email, ip, ticket)
        raise
    if not found:
        # La línea del log va después del 401, como la bitácora del correo que existe (RC-302).
        return JSONResponse({'detail': INVALID}, status_code=401,
                            background=BackgroundTask(_log_unknown_email, email, ip))

    org, user_id = str(found['organization_id']), str(found['user_id'])
    if not good:
        # El fallo ya contó arriba. La bitácora se escribe después de mandar el 401. Escrita antes, la conexión y el
        # INSERT hacían que un correo que existe tardara unos 17 ms más que uno que no existe.
        # Con raise HTTPException la tarea no correría: por eso se devuelve el mismo 401 a mano.
        return _bad_password(org, user_id, ip)
    # La contraseña es correcta: el intento no fue un fallo y se devuelve, al correo y a la IP.
    sessions.refund_login_attempt(email, ip, ticket)

    operator_mfa_required = False
    # La huella que abrió esta contraseña. Si cambia antes de crear la sesión (un restablecimiento o un /password en
    # paralelo), la sesión no se crea con la contraseña anterior (H7 de la revisión de RC-335).
    huella = found['password_hash']
    with transaction(org) as conn:
        if passwords.needs_rehash(found['password_hash'], user_id):
            # Una huella vieja sin cifrar queda cifrada en este mismo inicio de sesión (RC-330). Solo si nadie la
            # cambió desde la búsqueda: así un cambio de contraseña en paralelo no se pisa con la anterior.
            # Sin fila cambiada, otra petición guardó una huella nueva mientras tanto: la de un login en paralelo de
            # la misma cuenta (doble clic), que la cifró con esta misma contraseña, o la de un cambio de contraseña.
            # Se relee y solo entra si la contraseña también abre la huella que quedó.
            nueva = passwords.hash_password(body.password, user_id)
            if conn.execute('UPDATE users SET password_hash = %s WHERE id = %s AND password_hash = %s',
                            (nueva, user_id, found['password_hash'])).rowcount:
                huella = nueva
            else:
                actual = conn.execute('SELECT password_hash FROM users WHERE id = %s', (user_id,)).fetchone()
                if not actual or not passwords.verify_password(actual['password_hash'], body.password, user_id):
                    # Ya no abre la huella de ahora: vuelve a contar como fallo y queda en la bitácora como el otro 401.
                    sessions.register_fail(email, ip)
                    return _bad_password(org, user_id, ip)
                huella = actual['password_hash']
        if found['mfa_enabled']:
            # Los fallos del correo se borran hasta que el código sea correcto. Borrados aquí, quien
            # tiene la contraseña repetiría el login y 5 códigos sin llegar nunca al bloqueo. El mfa_token lleva la
            # marca de la huella: si la contraseña cambia antes del código, ya no sirve (H6 de la revisión de RC-335).
            return {'mfa_required': True, 'mfa_token': sessions.create_mfa(
                {'user_id': user_id, 'org_id': org, 'email': email, 'tag': sessions.password_tag(huella)})}
        # login_lookup() no devuelve el rol (migración 004): se lee aquí con RLS, como en /mfa/verify.
        # FOR NO KEY UPDATE (RC-154), como el UPDATE de last_login_at que viene: un alta de TOTP a la vez espera
        # a que esta sesión entre al índice y la cierra, o esta lectura espera al alta y la ve ya activa. Con FOR
        # SHARE dos logins a la vez de la misma cuenta chocaban en un deadlock al subir al lock del UPDATE.
        row = conn.execute('SELECT role, password_hash, %s AS mfa_enabled FROM users WHERE id = %%s AND is_active '
                           'FOR NO KEY UPDATE' % MFA_ENABLED_SQL, (user_id,)).fetchone()
        if not row:  # se desactivó la cuenta entre la búsqueda y aquí
            raise HTTPException(401, INVALID)
        if row['password_hash'] != huella:
            # Otra petición cambió la huella después de revisar la contraseña: un restablecimiento o un /password que ya
            # cerró las sesiones, o un login en paralelo que la cifró (RC-330). Solo sigue si la contraseña también abre
            # la de ahora; si no, cuenta como fallo, como arriba (H7 de la revisión de RC-335).
            if not passwords.verify_password(row['password_hash'], body.password, user_id):
                sessions.register_fail(email, ip)
                return _bad_password(org, user_id, ip)
            huella = row['password_hash']
        if row['mfa_enabled']:  # se activó entre la búsqueda y aquí
            return {'mfa_required': True, 'mfa_token': sessions.create_mfa(
                {'user_id': user_id, 'org_id': org, 'email': email, 'tag': sessions.password_tag(huella)})}
        # Una cuenta 'operator' de la consola del integrador (#66, RC-126, migración 033) o un superadmin (027) no entra
        # con solo la contraseña: primero activa su TOTP (comentario 10270 de RC-126, punto 2).
        operator_mfa_required = row['role'] == 'operator' or bool(conn.execute(
            'SELECT public.platform_operator_requires_mfa(%s) AS required', (user_id,)).fetchone()['required'])
        if operator_mfa_required:
            audit(conn, org, 'auth.operator_mfa_required', user_id, ip, 'user', user_id)
        else:
            user = _start_session(response, conn, {'id': user_id, 'organization_id': org, 'role': row['role'],
                                                    'email': email}, ip, 'password')
    if operator_mfa_required:
        raise HTTPException(403, OPERATOR_MFA_REQUIRED)
    _clear_fails(email)
    return {'mfa_required': False, 'user': user}


@router.post('/mfa/verify', summary='Segundo paso: código de 6 dígitos de la app autenticadora')
def verify_mfa(body: MfaIn, request: Request, response: Response):
    # El intento se gasta antes de revisar el código, en el mfa_token y en el correo, para que ni
    # las peticiones en paralelo ni volver a iniciar sesión den más de 5 códigos.
    pending = sessions.take_mfa(body.mfa_token)
    if pending and ('email' not in pending or 'tag' not in pending):  # token creado antes de este cambio
        sessions.delete_mfa(body.mfa_token)
        pending = None
    if not pending:
        raise HTTPException(401, MFA_EXPIRED)
    ip = client_ip(request)
    org, user_id, email = pending['org_id'], pending['user_id'], pending['email']
    if not sessions.take_mfa_attempt(email, ip):
        return _locked(BackgroundTask(_record_mfa_locked, org, user_id, email, ip))
    with transaction(org) as conn:
        # FOR NO KEY UPDATE, el mismo lock que /login, /password y el restablecimiento (RC-335): un cambio de contraseña a
        # la vez espera a que esta sesión entre al índice y la cierra, o esta lectura espera al cambio y ve la huella
        # nueva. Con otra huella que la del login que dio el mfa_token, ya no sirve (H6 de la revisión de RC-335).
        row = conn.execute(
            'SELECT email::text, role, password_hash, totp_secret_enc, last_totp_step FROM users '
            ' WHERE id = %s AND is_active FOR NO KEY UPDATE', (user_id,)).fetchone()
        if not row or not row['totp_secret_enc'] or sessions.password_tag(row['password_hash']) != pending['tag']:
            sessions.delete_mfa(body.mfa_token)
            raise HTTPException(401, MFA_EXPIRED)
        step = totp.verify_code(totp.decrypt_secret(row['totp_secret_enc'], user_id), body.code, row['last_totp_step'])
        # El UPDATE solo guarda el paso si ninguna otra petición (otro /mfa/verify o el registro de una passkey) gastó ese
        # código o uno posterior. Si no cambia nada, es un código usado.
        if step is not None and not conn.execute(
                'UPDATE users SET last_totp_step = %s WHERE id = %s AND (last_totp_step IS NULL OR last_totp_step < %s)',
                (step, user_id, step)).rowcount:
            step = None
        if step is None:
            audit(conn, org, 'auth.mfa_failed', user_id, ip, 'user', user_id)
            fail = True
        else:
            fail = False
            sessions.delete_mfa(body.mfa_token)
            # Después de un enlace al correo (#28, RC-63) la bitácora dice link_totp; si no, totp.
            via = 'link_totp' if pending.get('via') == 'link_totp' else 'totp'
            user = _start_session(response, conn, {'id': user_id, 'organization_id': org, 'role': row['role'], 'email': row['email']}, ip, via)
    if fail:
        sessions.register_mfa_fail(ip)
        raise HTTPException(401, MFA_INVALID)
    _clear_fails(email)
    return {'user': user}


# ------------------------------------------------------------------ enlace al correo (#28, RC-63)

# El mismo texto para todos, exista o no la cuenta, y aunque el enlace no salga (decisión 7 de RC-327).
LINK_SENT = ('Si el correo tiene cuenta, te enviamos un enlace que vence en 15 minutos. '
             'Si no llega, puedes entrar con tu contraseña o con una passkey.')
LINK_INVALID = 'El enlace no es válido o ya venció. Pide otro o entra con tu contraseña.'
LINK_MINUTES = sessions.LINK_SECONDS // 60
LINK_DAILY_DEFAULT = 80  # debajo de los 100 al día de Resend Free: deja cupo para otros correos (RC-317)


class LinkRequestIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    captcha: str | None = Field(default=None, max_length=captcha.MAX_PAYLOAD)


class LinkVerifyIn(BaseModel):
    token: str = Field(min_length=20, max_length=100)


def _portal_url():
    """La dirección del portal para el enlace: de PORTAL_URL, nunca de la cabecera Host de la petición. Vacía, el primer
    origen de ALLOWED_ORIGINS: así la deja docker-compose.despliegue.yml, para que la VM mande a https://lowtidesec.com
    y el plan B de pruebas a https://pruebas.lowtidesec.com (M4 de la revisión). Sin las dos, http://localhost:3000."""
    return (config('PORTAL_URL') or origenes_permitidos()[0]).rstrip('/')


def _link_daily_cap():
    try:
        return max(0, int(config('ENLACE_TOPE_DIARIO') or LINK_DAILY_DEFAULT))
    except ValueError:
        return LINK_DAILY_DEFAULT


def _send_link(email, ip):
    """Corre después del 202, así que la respuesta tarda lo mismo exista o no la cuenta. Ni el token ni el enlace van
    al log ni a la bitácora; el correo solo va a Resend."""
    try:
        if not sessions.take_link_request(email, ip):
            log.warning('enlace: límite de pedidos alcanzado: ip=%r dominio=%r', ip, _email_domain(email))
            return
        with transaction() as conn:
            found = conn.execute('SELECT * FROM login_lookup(%s)', (email,)).fetchone()
        if not found:
            log.warning('enlace pedido para un correo que no existe: ip=%r dominio=%r', ip, _email_domain(email))
            return
        if found['password_hash'] == HASH_DE_RELLENO:
            # Una cuenta de demo apagada (cirdan/auth/demo.py) sigue activa con el hash de relleno y sin MFA: con el
            # enlace entraría sin contraseña ni código. No se le manda nada ni gasta el tope (A1 de la revisión).
            log.warning('enlace pedido para una cuenta sin contraseña (hash de relleno): ip=%r dominio=%r', ip,
                        _email_domain(email))
            return
        org, user_id = str(found['organization_id']), str(found['user_id'])
        tope = _link_daily_cap()
        reservado = sessions.reserve_link_send(tope, user_id)
        if reservado < 0:
            log.warning('enlace: tope diario de la cuenta alcanzado (%d): ip=%r dominio=%r',
                        sessions.MAX_LINKS_USER_DAY, ip, _email_domain(email))
            return
        if not reservado:
            # Texto fijo para contar cuántas veces sale en la semana (decisión 7 de RC-327, README).
            log.warning('enlace: tope diario alcanzado (%d)', tope)
            return
        # Con la marca de la huella: si la contraseña cambia antes del canje, el enlace ya no sirve (H6 de RC-335).
        token = sessions.create_link({'user_id': user_id, 'org_id': org, 'email': email,
                                      'tag': sessions.password_tag(found['password_hash'])})
        motivo = correo.enviar_enlace(email, '%s/login/enlace#t=%s' % (_portal_url(), token), LINK_MINUTES)
        if motivo:
            sessions.delete_link(token)  # un enlace que no llegó no queda vivo
        with transaction(org) as conn:
            if motivo:
                audit(conn, org, 'auth.link_send_failed', user_id, ip, 'user', user_id, {'reason': motivo})
            else:
                audit(conn, org, 'auth.link_sent', user_id, ip, 'user', user_id, {'expires_minutes': LINK_MINUTES})
    except Exception:
        log.exception('enlace: falló el envío en segundo plano')


def _audit_link_trace(token, ip):
    """Un token que ya no sirve pero fue de una cuenta (usado, anulado por otro o vencido) queda en la bitácora de esa
    cuenta como auth.link_rejected, sin el token (H7, M3 de la revisión). Una vez por token: los reintentos del mismo
    no escriben más. Si falla, queda solo en el log: el 401 sale igual."""
    try:
        rastro = sessions.link_trace(token)
        if rastro:
            with transaction(rastro['org_id']) as conn:
                audit(conn, rastro['org_id'], 'auth.link_rejected', rastro['user_id'], ip, 'user', rastro['user_id'],
                      {'reason': rastro['reason']})
    except Exception:
        log.exception('enlace: no se pudo escribir auth.link_rejected del canje rechazado')


@router.post('/link/request', status_code=202,
             summary='Pide un enlace para entrar por correo; responde igual exista o no la cuenta')
def request_link(body: LinkRequestIn, request: Request):
    # El captcha va primero, como en /login: sin él no se cuenta nada ni se busca el correo. Con el tope diario debajo
    # de 100, sin captcha unas cuantas IP dejarían a todos sin enlace ese día.
    if not captcha.verify(body.captcha):
        raise HTTPException(400, CAPTCHA_INVALID)
    email = body.email.strip().lower()
    return JSONResponse({'detail': LINK_SENT}, status_code=202, headers=NO_STORE,
                        background=BackgroundTask(_send_link, email, client_ip(request)))


@router.post('/link/verify', summary='Canjea el enlace del correo por la sesión; con MFA pide el código')
def verify_link(body: LinkVerifyIn, request: Request, response: Response):
    pending = sessions.take_link(body.token)  # una sola vez, también con dos canjes a la vez
    if not pending:
        _audit_link_trace(body.token, client_ip(request))
        raise HTTPException(401, LINK_INVALID)
    ip = client_ip(request)
    org, user_id, email = pending['org_id'], pending['user_id'], pending['email']
    rejected = None
    with transaction(org) as conn:
        # Como /login: la cuenta sigue activa y su empresa en trial o active, con la fila bloqueada contra un alta de
        # TOTP a la vez (FOR NO KEY UPDATE, RC-154).
        row = conn.execute(
            'SELECT u.role, u.email::text, u.mfa_enabled_at IS NOT NULL AND u.totp_secret_enc IS NOT NULL AS mfa_enabled, '
            '       u.password_hash = %s AS demo_off, u.password_hash '
            '  FROM users u JOIN organizations o ON o.id = u.organization_id '
            " WHERE u.id = %s AND u.is_active AND o.status IN ('trial', 'active') FOR NO KEY UPDATE OF u",
            (HASH_DE_RELLENO, user_id)).fetchone()
        if not row:
            rejected = 'inactive'
        elif row['demo_off']:
            # Apagada después de pedir el enlace: tampoco entra (A1 de la revisión).
            rejected = 'demo_off'
        elif sessions.password_tag(row['password_hash']) != pending.get('tag'):
            # La contraseña cambió después de pedir el enlace (un restablecimiento o /password), o es un enlace de antes
            # de la marca: ya no entra (H6 de la revisión de RC-335).
            rejected = 'password_changed'
        elif row['mfa_enabled']:
            return {'mfa_required': True, 'mfa_token': sessions.create_mfa(
                {'user_id': user_id, 'org_id': org, 'email': row['email'], 'via': 'link_totp',
                 'tag': sessions.password_tag(row['password_hash'])})}
        elif row['role'] == 'operator' or conn.execute(
                'SELECT public.platform_operator_requires_mfa(%s) AS required', (user_id,)).fetchone()['required']:
            rejected = 'operator_mfa_required'
        else:
            user = _start_session(response, conn, {'id': user_id, 'organization_id': org, 'role': row['role'],
                                                    'email': row['email']}, ip, 'link')
        if rejected:
            audit(conn, org, 'auth.link_rejected', user_id, ip, 'user', user_id, {'reason': rejected})
    # Fuera del with: con raise adentro, la transacción se desharía y la bitácora no quedaría.
    if rejected == 'operator_mfa_required':
        raise HTTPException(403, OPERATOR_MFA_REQUIRED)
    if rejected:
        raise HTTPException(401, LINK_INVALID)
    _clear_fails(email)
    return {'mfa_required': False, 'user': user}


# ------------------------------------------------------------------ recuperar la contraseña con un enlace (RC-335)

# El mismo texto para todos, exista o no la cuenta, y aunque el enlace no salga.
RESET_SENT = ('Si el correo tiene cuenta, te enviamos un enlace para elegir una contraseña nueva. Vence en 30 minutos. '
              'Si no llega, pide a un Administrador de tu organización que restablezca tu contraseña.')
RESET_INVALID = 'El enlace no es válido o ya venció. Pide otro desde «¿Olvidaste tu contraseña?».'
RESET_AGAIN = ' El enlace ya se usó: pide otro.'
RESET_LENGTH = 'La contraseña nueva debe tener entre %d y %d caracteres.' % (passwords.MIN_LENGTH, passwords.MAX_LENGTH)
RESET_DONE = 'Tu contraseña cambió y cerramos todas tus sesiones. Inicia sesión con la nueva.'
RESET_MINUTES = sessions.RESET_SECONDS // 60
RESET_REJECTED_REASONS = {'comun': 'common', 'filtrada': 'pwned'}


class PasswordResetIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    captcha: str | None = Field(default=None, max_length=captcha.MAX_PAYLOAD)


class PasswordResetConfirmIn(BaseModel):
    token: str = Field(min_length=20, max_length=100)
    # Sin largo en el modelo: el token se gasta antes de revisar la contraseña (Hecho cuando, punto 2), y un 422 del
    # modelo saldría antes y lo dejaría vivo (H9 de la revisión). El cuerpo ya lo acota el tope global de main.py.
    new_password: str


def _send_reset(email, ip):
    """Corre después del 202, así que la respuesta tarda lo mismo exista o no la cuenta. Ni el token ni el enlace van
    al log ni a la bitácora; el correo solo va a Resend."""
    try:
        if not sessions.take_reset_request(email, ip):
            log.warning('recuperar: límite de pedidos alcanzado: ip=%r dominio=%r', ip, _email_domain(email))
            return
        with transaction() as conn:
            found = conn.execute('SELECT * FROM login_lookup(%s)', (email,)).fetchone()
        if not found:
            log.warning('recuperar pedido para un correo que no existe: ip=%r dominio=%r', ip, _email_domain(email))
            return
        if found['password_hash'] == HASH_DE_RELLENO:
            # Una cuenta de demo apagada (cirdan/auth/demo.py) no se revive con una contraseña nueva, como en RC-63.
            log.warning('recuperar pedido para una cuenta sin contraseña (hash de relleno): ip=%r dominio=%r', ip,
                        _email_domain(email))
            return
        org, user_id = str(found['organization_id']), str(found['user_id'])
        reservado = sessions.reserve_link_send(_link_daily_cap(), user_id, tipo='reset')
        if reservado <= 0:
            motivo = 'tope_cuenta' if reservado < 0 else 'tope_diario'
            log.warning('recuperar: %s alcanzado', motivo)
            token = None
        else:
            # Sin el correo (H5 de la revisión) y con la marca de la huella: si la contraseña cambia antes del canje
            # (por /password o por otro enlace), este ya no sirve (H2).
            token = sessions.create_reset({'user_id': user_id, 'org_id': org,
                                           'tag': sessions.password_tag(found['password_hash'])})
            motivo = correo.enviar_recuperacion(email, '%s/forgot-password/reset#t=%s' % (_portal_url(), token),
                                                RESET_MINUTES)
            if motivo:
                sessions.delete_reset(token)  # un enlace que no llegó no queda vivo, y el anterior sigue (H4)
            else:
                sessions.activate_reset(user_id, token)  # salió: ahora sí anula el anterior
        with transaction(org) as conn:
            if motivo:
                audit(conn, org, 'auth.password_reset_send_failed', user_id, ip, 'user', user_id, {'reason': motivo})
            else:
                audit(conn, org, 'auth.password_reset_requested', user_id, ip, 'user', user_id,
                      {'expires_minutes': RESET_MINUTES})
    except Exception:
        log.exception('recuperar: falló el envío en segundo plano')


def _after_reset(user_id, org, email, ip):
    """Después de responder: borra los fallos de login y de cambio de contraseña y manda el aviso. Si algo falla queda
    en el log: la contraseña ya cambió y las sesiones ya se cerraron."""
    try:
        sessions.clear_fails(email)
    except Exception:
        log.exception('recuperar: no se pudieron borrar los fallos de login del usuario %s', user_id)
    _clear_password_attempts(user_id)
    try:
        reservado = sessions.reserve_link_send(_link_daily_cap(), user_id, tipo='aviso')
        motivo = ('tope_cuenta' if reservado < 0 else 'tope_diario') if reservado <= 0 \
            else correo.enviar_aviso_cambio(email)
        if motivo:
            with transaction(org) as conn:
                audit(conn, org, 'auth.password_reset_notice_failed', user_id, ip, 'user', user_id, {'reason': motivo})
    except Exception:
        log.exception('recuperar: no se pudo mandar el aviso de contraseña cambiada del usuario %s', user_id)


def _reset_rejected(org, user_id, ip, reason, detail):
    """El token ya se gastó: deja el rechazo en la bitácora de la cuenta (sin la contraseña) y responde 400."""
    with transaction(org) as conn:
        audit(conn, org, 'auth.password_reset_rejected', user_id, ip, 'user', user_id, {'reason': reason})
    raise HTTPException(400, detail)


@router.post('/password-reset', status_code=202,
             summary='Pide un enlace para recuperar la contraseña; responde igual exista o no la cuenta')
def request_password_reset(body: PasswordResetIn, request: Request):
    # El captcha va primero, como en /login y /link/request: sin él no se cuenta nada ni se busca el correo.
    if not captcha.verify(body.captcha):
        raise HTTPException(400, CAPTCHA_INVALID)
    email = body.email.strip().lower()
    return JSONResponse({'detail': RESET_SENT}, status_code=202, headers=NO_STORE,
                        background=BackgroundTask(_send_reset, email, client_ip(request)))


@router.post('/password-reset/confirm',
             summary='Canjea el enlace de recuperación por una contraseña nueva y cierra todas las sesiones')
def confirm_password_reset(body: PasswordResetConfirmIn, request: Request):
    # El token se gasta antes de revisar nada (Hecho cuando, punto 2): una sola vez, también con dos canjes a la vez.
    pending = sessions.take_reset(body.token)
    if not pending:
        raise HTTPException(400, RESET_INVALID)
    ip = client_ip(request)
    org, user_id = pending['org_id'], pending['user_id']
    new = body.new_password
    if not passwords.MIN_LENGTH <= len(new) <= passwords.MAX_LENGTH:
        _reset_rejected(org, user_id, ip, 'length', RESET_LENGTH + RESET_AGAIN)
    topada = []

    def permitir():
        # El mismo tope por usuario de consultas a Pwned Passwords que /password (RC-334).
        if sessions.take_pwned_check(user_id) > sessions.MAX_PWNED_CHECKS:
            topada.append(True)
            return False
        return True
    # Antes de bloquear la fila: la consulta a la API tarda hasta 2 s.
    revision = passwords.revisar_nueva(new, permitir)
    if revision.problema:
        _reset_rejected(org, user_id, ip, RESET_REJECTED_REASONS[revision.problema],
                        NEW_PASSWORD_PROBLEMS[revision.problema] + RESET_AGAIN)
    rejected = None
    with transaction(org) as conn:
        # Como /link/verify: la cuenta sigue activa y su empresa en trial o active, y no es una de demo apagada. FOR NO
        # KEY UPDATE, el mismo lock que /login y /password: un cambio a la vez.
        row = conn.execute(
            'SELECT u.email::text, u.password_hash = %s AS demo_off, u.password_hash '
            '  FROM users u JOIN organizations o ON o.id = u.organization_id '
            " WHERE u.id = %s AND u.is_active AND o.status IN ('trial', 'active') FOR NO KEY UPDATE OF u",
            (HASH_DE_RELLENO, user_id)).fetchone()
        if not row:
            rejected = 'inactive'
        elif row['demo_off']:
            rejected = 'demo_off'
        elif sessions.password_tag(row['password_hash']) != pending.get('tag'):
            # La contraseña cambió después de pedir el enlace (/password u otro enlace): este ya no sirve (H2).
            rejected = 'password_changed'
        else:
            conn.execute('UPDATE users SET password_hash = %s, updated_at = now() WHERE id = %s',
                         (passwords.hash_password(new, user_id), user_id))
            # Como /password: quien tenía la contraseña anterior pudo registrar una passkey sin TOTP (RC-331). Se borran
            # antes de cualquier audit(), para no esperar una fila de passkey con el candado de la bitácora. El TOTP
            # no se toca: el siguiente inicio de sesión lo pide.
            removed = conn.execute('DELETE FROM webauthn_credentials WHERE user_id = %s RETURNING id::text',
                                   (user_id,)).fetchall()
            for passkey in removed:
                audit(conn, org, 'auth.passkey_deleted', user_id, ip, 'passkey', passkey['id'],
                      {'reason': 'password_reset'})
            audit(conn, org, 'auth.password_reset', user_id, ip, 'user', user_id, {'passkeys_removed': len(removed)})
            if revision.sin_respuesta:
                audit(conn, org, 'auth.pwned_check_unavailable', user_id, ip, 'user', user_id,
                      {'fallback': 'common_list', 'reason': 'rate_limited'} if topada else {'fallback': 'common_list'})
            # Todas las sesiones de la cuenta, en cualquier empresa. Antes del commit, como /password: si Valkey falla,
            # la contraseña no cambia (el token sí queda gastado y se pide otro).
            sessions.delete_others(user_id, None)
        if rejected:
            audit(conn, org, 'auth.password_reset_rejected', user_id, ip, 'user', user_id, {'reason': rejected})
    if rejected:
        raise HTTPException(400, RESET_INVALID)
    response = JSONResponse({'detail': RESET_DONE, 'passkeys_removed': len(removed)}, headers=NO_STORE,
                            background=BackgroundTask(_after_reset, user_id, org, row['email'].lower(), ip))
    # La sesión de este navegador, si había, ya se cerró: sin la cookie, /login muestra el aviso en vez de rebotar a
    # /dashboard y a «Tu sesión ya no es válida» (H8 de la revisión).
    response.delete_cookie(COOKIE, path='/', httponly=True, secure=COOKIE_SECURE, samesite='lax')
    return response


MFA_ALREADY ='La verificación en dos pasos ya está activa en tu cuenta.'
MFA_SETUP_EXPIRED = 'El código QR venció o ya se usaron sus 5 intentos. Empieza de nuevo.'
WRONG_PASSWORD = 'La contraseña actual no es correcta.'
SESSION_ENDED = 'Tu sesión terminó. Vuelve a iniciar sesión.'
NO_STORE = {'Cache-Control': 'no-store'}
MFA_ENABLED_SQL = 'mfa_enabled_at IS NOT NULL AND totp_secret_enc IS NOT NULL'


class MfaSetupIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=passwords.MAX_LENGTH)


class MfaEnableIn(BaseModel):
    code: str = Field(pattern=totp.CODE_PATTERN)


@router.post('/mfa/setup', summary='Alta de TOTP, paso 1: con la contraseña, un secreto nuevo con su QR')
def mfa_setup(body: MfaSetupIn, request: Request, response: Response, session: Session = Depends(current_session)):
    # Pide la contraseña para que una cookie robada no baste para atar la cuenta a la app de otra persona.
    # Una contraseña equivocada cuenta para el bloqueo del login, igual que en /login.
    ip = client_ip(request)
    if sessions.is_locked(session.email, ip):
        raise HTTPException(429, LOCKED, headers={'Retry-After': str(sessions.LOCK_SECONDS)})
    with transaction(session.own_org_id) as conn:
        row = conn.execute('SELECT email::text, password_hash, %s AS mfa_enabled FROM users WHERE id = %%s AND is_active'
                           % MFA_ENABLED_SQL, (session.user_id,)).fetchone()
        if not row:
            sessions.delete(session.token)
            raise HTTPException(401, SESSION_ENDED)
        bad_password = not passwords.verify_password(row['password_hash'], body.current_password, session.user_id)
        if bad_password:
            audit(conn, session.own_org_id, 'auth.mfa_setup_failed', session.user_id, ip, 'user', session.user_id,
                  {'reason': 'password'})
        elif row['mfa_enabled']:
            raise HTTPException(409, MFA_ALREADY)
        else:
            audit(conn, session.own_org_id, 'auth.mfa_setup_started', session.user_id, ip, 'user', session.user_id)
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
    removed = []
    with transaction(session.own_org_id) as conn:
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
            audit(conn, session.own_org_id, 'auth.mfa_enable_failed', session.user_id, ip, 'user', session.user_id)
        else:
            # last_totp_step con el paso de este código: el mismo código no sirve después para iniciar sesión.
            conn.execute('UPDATE users SET totp_secret_enc = %s, mfa_enabled_at = now(), last_totp_step = %s, '
                         'updated_at = now() WHERE id = %s',
                         (totp.encrypt_secret(secret, session.user_id), step, session.user_id))
            audit(conn, session.own_org_id, 'auth.mfa_enabled', session.user_id, ip, 'user', session.user_id)
            # Las passkeys de la cuenta se registraron sin TOTP, solo con la contraseña (RC-331): quien la tenía pudo dar
            # de alta la suya y seguiría entrando sin el código. Se borran y se vuelven a registrar con el código.
            removed = _delete_passkeys(conn, session, ip, 'mfa_enabled')
            # Las demás sesiones de la cuenta entraron sin el segundo factor: se cierran y solo queda la que activó.
            # Va antes del commit y con la fila bloqueada: si Valkey falla, el alta no se guarda y se puede repetir.
            sessions.delete_others(session.user_id, session.token)
    if step is None:
        sessions.register_mfa_fail(ip)
        raise HTTPException(400, MFA_INVALID)
    sessions.delete_mfa_setup(session.user_id)
    return {'mfa_enabled': True, 'passkeys_removed': len(removed)}


@router.post('/logout', status_code=204, summary='Cierra la sesión y la borra del servidor')
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    # La cookie se borra antes de tocar Valkey y ninguna falla de Valkey sale de aquí: con una excepción, el 500 de
    # main.py no lleva el Set-Cookie de este Response y el navegador conservaría la cookie.
    response.delete_cookie(COOKIE, path='/', httponly=True, secure=COOKIE_SECURE, samesite='lax')
    try:
        data = sessions.get(token)
    except Exception:  # se intenta borrar igual: la sesión puede existir aunque no se haya podido leer
        data = None
        log.exception('No se pudo leer la sesión al cerrar sesión. Se borró la cookie y se intenta borrar la sesión')
    # Primero se borran la sesión y la cookie: si la base falla al escribir el evento, la persona igual sale (RC-314).
    try:
        sessions.delete(token)
    except Exception:  # puede seguir en Valkey hasta que venza por inactividad: no se escribe auth.logout
        log.exception('No se pudo borrar de Valkey la sesión del usuario %s al cerrar sesión. Se borró la cookie',
                      data['user_id'] if data else 'desconocido')
        return
    if data:
        # La bitácora va en la empresa de la cuenta, aunque un superadmin cierre sesión desde otra (RC-332).
        home = data.get('home_org_id') or data['org_id']
        try:
            with transaction(home) as conn:
                audit(conn, home, 'auth.logout', data['user_id'], client_ip(request), 'user', data['user_id'])
        except Exception:  # la sesión ya no existe: se responde 204 y la falla queda en el log, sin el token
            log.exception('No se pudo escribir auth.logout del usuario %s', data['user_id'])


@router.get('/me', summary='Usuario de la sesión')
def me(session: Session = Depends(current_session)):
    with transaction(session.own_org_id) as conn:
        user = _user(conn, session.user_id)
    if not user:  # se desactivó la cuenta con la sesión abierta
        sessions.delete(session.token)
        raise HTTPException(401, 'Tu sesión terminó. Vuelve a iniciar sesión.')
    return dict(user, **platform_view(session, user), **sessions.limits(session.created_at))


COMMON_PASSWORD = 'Esa contraseña es muy común. Elige otra.'
PWNED_PASSWORD = 'Esa contraseña salió en una filtración conocida. Elige otra.'
NEW_PASSWORD_PROBLEMS = {'comun': COMMON_PASSWORD, 'filtrada': PWNED_PASSWORD}
WRONG_PASSWORD_LAST = 'La contraseña actual no es correcta. Por seguridad cerramos tu sesión: vuelve a iniciarla.'


def _clear_password_attempts(user_id):
    # Corre con la contraseña ya cambiada. Si Valkey falla aquí, el contador vence solo en 15 min: un 500 diría que no
    # cambió cuando sí cambió.
    try:
        sessions.clear_password_attempts(user_id)
    except Exception:
        log.exception('No se pudieron borrar los intentos de cambio de contraseña del usuario %s', user_id)


@router.post('/password', summary='Cambia la contraseña del usuario de la sesión y borra sus passkeys')
def change_password(body: PasswordIn, request: Request, session: Session = Depends(current_session)):
    # La lista de contraseñas comunes (RC-281) y Pwned Passwords (RC-334) van primero: no revisan la contraseña actual,
    # así que no gastan un intento, y la consulta a la API (hasta 2 s) no espera con la fila de la cuenta bloqueada.
    # Por eso las consultas a la API llevan su propio tope por usuario: pasado, se revisa solo con la lista local.
    topada = []

    def permitir():
        if sessions.take_pwned_check(session.user_id) > sessions.MAX_PWNED_CHECKS:
            topada.append(True)
            return False
        return True
    revision = passwords.revisar_nueva(body.new_password, permitir)
    if revision.problema:
        raise HTTPException(400, NEW_PASSWORD_PROBLEMS[revision.problema])
    # El intento se cuenta antes de revisar la contraseña actual (RC-290), como en /mfa/verify: en paralelo tampoco se
    # revisan más de 5. Es un contador del usuario, aparte del login: quien tiene una cookie robada no bloquea el
    # inicio de sesión del dueño, y el quinto fallo le cierra la sesión.
    attempt = sessions.take_password_attempt(session.user_id)
    if attempt > sessions.MAX_PASSWORD_ATTEMPTS:
        raise HTTPException(429, LOCKED, headers={'Retry-After': str(sessions.LOCK_SECONDS)})
    ip = client_ip(request)
    last = attempt == sessions.MAX_PASSWORD_ATTEMPTS
    with transaction(session.own_org_id) as conn:
        # FOR NO KEY UPDATE: dos cambios a la vez con la contraseña actual ya no dan 204 los dos. El segundo espera el
        # commit del primero y revisa contra el hash nuevo (si no, ganaba el último, que podía ser el de una cookie
        # robada). No FOR UPDATE: chocaría con el FOR KEY SHARE de la llave de audit_log a users y un login fallido a la
        # vez daría deadlock con el lock de la cadena. Es el mismo lock que toma el login.
        row = conn.execute('SELECT password_hash FROM users WHERE id = %s FOR NO KEY UPDATE',
                           (session.user_id,)).fetchone()
        ok = bool(row) and passwords.verify_password(row['password_hash'], body.current_password, session.user_id)
        if not ok and last:
            audit(conn, session.own_org_id, 'auth.password_change_locked', session.user_id, ip, 'user', session.user_id,
                  {'attempts': attempt})
            # Antes del commit: si Valkey falla, el evento no queda sin que la sesión se haya cerrado.
            sessions.delete(session.token)
        elif ok:
            conn.execute('UPDATE users SET password_hash = %s, updated_at = now() WHERE id = %s',
                         (passwords.hash_password(body.new_password, session.user_id), session.user_id))
            # Sin TOTP una passkey se registra solo con la contraseña (RC-331): quien tenía la anterior pudo dar de
            # alta la suya y seguiría entrando, como MFA, después del cambio. Se borran y se vuelven a registrar con
            # la nueva. El borrado va antes de cualquier audit(): así no se espera una fila de passkey con el candado
            # de la bitácora.
            removed = _delete_passkeys(conn, session, ip, 'password_changed')
            audit(conn, session.own_org_id, 'auth.password_changed', session.user_id, ip, 'user', session.user_id)
            if revision.sin_respuesta:
                # Pwned Passwords no respondió en 2 s y la nueva solo pasó la lista local (decisión 2 de RC-334). Sin
                # la contraseña ni su SHA-1.
                # Con el tope por usuario pasado, el motivo lo dice.
                audit(conn, session.own_org_id, 'auth.pwned_check_unavailable', session.user_id, ip, 'user',
                      session.user_id, {'fallback': 'common_list', 'reason': 'rate_limited'} if topada
                      else {'fallback': 'common_list'})
            # Las demás sesiones de la cuenta se cierran y queda la que cambió. Va antes del commit, como en
            # /mfa/enable: si Valkey falla, la contraseña no cambia y se puede repetir.
            sessions.delete_others(session.user_id, session.token)
    if not ok:
        if last:
            response = JSONResponse({'detail': WRONG_PASSWORD_LAST}, status_code=400)
            response.delete_cookie(COOKIE, path='/', httponly=True, secure=COOKIE_SECURE, samesite='lax')
            return response
        raise HTTPException(400, WRONG_PASSWORD)
    _clear_password_attempts(session.user_id)
    return {'passkeys_removed': len(removed)}


def _delete_passkeys(conn, session, ip, reason):
    """Borra todas las passkeys de la cuenta de la sesión y deja un auth.passkey_deleted por cada una. En la bitácora
    va solo el id: el nombre es texto libre y audit_log no se puede borrar ni anonimizar."""
    removed = conn.execute('DELETE FROM webauthn_credentials WHERE user_id = %s RETURNING id::text',
                           (session.user_id,)).fetchall()
    for passkey in removed:
        audit(conn, session.own_org_id, 'auth.passkey_deleted', session.user_id, ip, 'passkey', passkey['id'],
              {'reason': reason})
    return removed


# ------------------------------------------------------------------ passkeys (RC-331)
# Otra forma de entrar, además de contraseña y TOTP, que siguen sirviendo. La passkey exige verificación del usuario
# (huella, rostro o PIN del dispositivo), así que entrar con ella cuenta como MFA: no se pide el código TOTP después.

PASSKEYS_OFF = 'Las passkeys no están disponibles en este servidor.'
PASSKEY_INVALID = 'No se pudo entrar con esa passkey. Inténtalo de nuevo o entra con tu correo y contraseña.'
PASSKEY_EXPIRED = 'La solicitud de la passkey venció. Inténtalo de nuevo.'
PASSKEY_REG_INVALID = 'No se pudo registrar la passkey. Inténtalo de nuevo.'
PASSKEY_REG_EXPIRED = 'La solicitud venció o ya se usó. Empieza de nuevo.'
PASSKEY_CODE_REQUIRED = 'Escribe el código de 6 dígitos de tu app autenticadora.'
PASSKEY_DUPLICATE = 'Esa passkey ya está registrada.'
PASSKEY_NOT_FOUND = 'No existe esa passkey.'
PASSKEY_OPTIONS_LIMIT = ('Se pidieron demasiadas passkeys desde tu red. Espera 15 minutos o entra con tu correo y '
                         'contraseña.')
MAX_PASSKEYS = 10
PASSKEY_LIMIT = 'Ya tienes %d passkeys. Borra una para registrar otra.' % MAX_PASSKEYS
PASSKEY_COLUMNS = 'id::text, name, created_at, last_used_at, backed_up, transports'


class PasskeyRegisterOptionsIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=passwords.MAX_LENGTH)
    # Solo si la cuenta tiene TOTP. Sin él, quien robe la cookie y la contraseña registraría su passkey y se saltaría
    # el segundo factor para siempre.
    code: str | None = Field(default=None, pattern=totp.CODE_PATTERN)


class PasskeyRegisterVerifyIn(BaseModel):
    credential: dict
    name: str = Field(min_length=1, max_length=60)


class PasskeyLoginVerifyIn(BaseModel):
    login_token: str = Field(min_length=10, max_length=100)
    credential: dict


def _passkeys_on():
    if not webauthn.configured():
        raise HTTPException(503, PASSKEYS_OFF)


def _audit_passkey_login_failed(org, user_id, ip, reason):
    # Como _audit_bad_password: si la bitácora falla, queda en el log y el 401 sale igual.
    try:
        with transaction(org) as conn:
            audit(conn, org, 'auth.login_failed', user_id, ip, 'user', user_id, {'reason': 'passkey', 'detail': reason})
    except Exception:
        log.exception('No se pudo escribir auth.login_failed (passkey) del usuario %s', user_id)


@router.post('/passkeys/register/options',
             summary='Registrar passkey, paso 1: con la contraseña y, si hay TOTP, un código, las opciones de WebAuthn')
def passkey_register_options(body: PasskeyRegisterOptionsIn, request: Request, response: Response,
                             session: Session = Depends(current_session)):
    _passkeys_on()
    ip = client_ip(request)
    if sessions.is_locked(session.email, ip):
        raise HTTPException(429, LOCKED, headers={'Retry-After': str(sessions.LOCK_SECONDS)})
    # El intento se cuenta antes de revisar la contraseña, con el mismo contador por usuario que /password (RC-290):
    # contado después, las peticiones en paralelo pasaban todas con el contador en 0 y se revisaban más de 5 (R3-1).
    if sessions.take_password_attempt(session.user_id) > sessions.MAX_PASSWORD_ATTEMPTS:
        raise HTTPException(429, LOCKED, headers={'Retry-After': str(sessions.LOCK_SECONDS)})
    fail = None
    # La fila del usuario solo se ve con RLS de su empresa: own_org_id, como /mfa/* y /password, para que un superadmin
    # que trabaja en otra empresa registre, vea y borre las suyas (R3-14, RC-332).
    with transaction(session.own_org_id) as conn:
        # FOR NO KEY UPDATE, como en /login: otra petición que gaste un código de esta cuenta espera a esta. /mfa/verify
        # no bloquea la fila al leer, pero su UPDATE solo guarda un paso posterior al guardado.
        row = conn.execute('SELECT email::text, full_name, password_hash, totp_secret_enc, last_totp_step, %s AS mfa_enabled '
                           'FROM users WHERE id = %%s AND is_active FOR NO KEY UPDATE' % MFA_ENABLED_SQL,
                           (session.user_id,)).fetchone()
        if not row:
            sessions.delete(session.token)
            raise HTTPException(401, SESSION_ENDED)
        existing = []
        if not passwords.verify_password(row['password_hash'], body.current_password, session.user_id):
            fail = 'password'
        else:
            # La contraseña es correcta: el contador vuelve a 0, como en /password. Va antes del 409 de abajo, que si
            # no gastaría un intento por cada vez que se pide con 10 passkeys.
            _clear_password_attempts(session.user_id)
            existing = [r['credential_id'] for r in conn.execute(
                'SELECT credential_id FROM webauthn_credentials WHERE user_id = %s', (session.user_id,)).fetchall()]
            # Antes del código: con 10 passkeys no se gasta el código ni se cuenta un intento.
            if len(existing) >= MAX_PASSKEYS:
                raise HTTPException(409, PASSKEY_LIMIT)
        if fail:
            pass
        elif row['mfa_enabled'] and not body.code:
            raise HTTPException(400, PASSKEY_CODE_REQUIRED)
        elif row['mfa_enabled']:
            # El código cuenta como fallo del correo antes de revisarlo, como en /mfa/verify.
            if not sessions.take_mfa_attempt(session.email, ip):
                raise HTTPException(429, LOCKED, headers={'Retry-After': str(sessions.LOCK_SECONDS)})
            step = totp.verify_code(totp.decrypt_secret(row['totp_secret_enc'], session.user_id), body.code,
                                    row['last_totp_step'])
            if step is None or not conn.execute(
                    'UPDATE users SET last_totp_step = %s WHERE id = %s AND (last_totp_step IS NULL OR last_totp_step < %s)',
                    (step, session.user_id, step)).rowcount:
                fail = 'code'
        if fail:
            audit(conn, session.own_org_id, 'auth.passkey_registration_failed', session.user_id, ip, 'user',
                  session.user_id, {'reason': fail})
        else:
            audit(conn, session.own_org_id, 'auth.passkey_registration_started', session.user_id, ip, 'user',
                  session.user_id)
    if fail == 'password':
        sessions.register_fail(session.email, ip)
        raise HTTPException(400, WRONG_PASSWORD)
    if fail == 'code':
        sessions.register_mfa_fail(ip)
        raise HTTPException(400, MFA_INVALID)
    if row['mfa_enabled']:
        _clear_fails(session.email)  # el código fue correcto, como en /mfa/verify
    options, challenge = webauthn.registration_options(session.user_id, row['email'], row['full_name'], existing)
    sessions.create_passkey_registration(session.user_id, session.token, challenge,
                                         sessions.password_tag(row['password_hash']))
    response.headers.update(NO_STORE)
    return {'options': options, 'expires_in_seconds': sessions.PASSKEY_SECONDS}


@router.post('/passkeys/register/verify', status_code=201,
             summary='Registrar passkey, paso 2: guarda la passkey si la respuesta del navegador es válida')
def passkey_register_verify(body: PasskeyRegisterVerifyIn, request: Request, session: Session = Depends(current_session)):
    _passkeys_on()
    name = body.name.strip()
    if not name:
        raise HTTPException(422, 'Ponle un nombre a la passkey.')
    # El reto se gasta antes de revisar la respuesta: una respuesta que no sirve obliga a empezar de nuevo, con la
    # contraseña y el código.
    pending = sessions.take_passkey_registration(session.user_id, session.token)
    if pending is None:
        raise HTTPException(400, PASSKEY_REG_EXPIRED)
    challenge, password_tag = pending
    ip = client_ip(request)
    try:
        data = webauthn.verify_registration(body.credential, challenge)
    except webauthn.PasskeyError as exc:
        log.info('Registro de passkey rechazado del usuario %s: %s', session.user_id, exc)
        with transaction(session.own_org_id) as conn:
            audit(conn, session.own_org_id, 'auth.passkey_registration_failed', session.user_id, ip, 'user',
                  session.user_id, {'reason': 'response'})
        raise HTTPException(400, PASSKEY_REG_INVALID)
    with transaction(session.own_org_id) as conn:
        user = conn.execute('SELECT password_hash FROM users WHERE id = %s AND is_active FOR NO KEY UPDATE',
                            (session.user_id,)).fetchone()
        if not user:
            sessions.delete(session.token)
            raise HTTPException(401, SESSION_ENDED)
        # Con la fila bloqueada, la contraseña debe ser la misma con la que se pidió el reto: un cambio de contraseña
        # en medio ya borró las passkeys, y este registro, empezado con la anterior, tampoco se guarda.
        if sessions.password_tag(user['password_hash']) != password_tag:
            raise HTTPException(400, PASSKEY_REG_EXPIRED)
        # Con la fila bloqueada, la sesión debe seguir viva: /mfa/enable borra las passkeys y cierra las demás sesiones
        # con la fila bloqueada. Una de esas sesiones que ya pasó current_session no guarda la suya después (R4).
        if not sessions.get(session.token):
            raise HTTPException(401, SESSION_ENDED)
        count = conn.execute('SELECT count(*) AS n FROM webauthn_credentials WHERE user_id = %s',
                             (session.user_id,)).fetchone()['n']
        if count >= MAX_PASSKEYS:
            raise HTTPException(409, PASSKEY_LIMIT)
        try:
            with conn.transaction():
                row = conn.execute(
                    'INSERT INTO webauthn_credentials (organization_id, user_id, credential_id, public_key, sign_count, '
                    'transports, aaguid, backed_up, name) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) '
                    'RETURNING ' + PASSKEY_COLUMNS,
                    (session.own_org_id, session.user_id, data['credential_id'], data['public_key'], data['sign_count'],
                     data['transports'], data['aaguid'], data['backed_up'], name)).fetchone()
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, PASSKEY_DUPLICATE)
        # Sin el nombre: es texto libre y audit_log no se puede borrar ni anonimizar.
        audit(conn, session.own_org_id, 'auth.passkey_registered', session.user_id, ip, 'passkey', row['id'],
              {'backed_up': data['backed_up']})
    return row


@router.post('/passkeys/login/options', summary='Entrar con passkey, paso 1: las opciones de WebAuthn y su token')
def passkey_login_options(request: Request, response: Response):
    _passkeys_on()
    ip = client_ip(request)
    # Una IP bloqueada por fallos no pide retos. Aparte, cada IP pide como máximo MAX_PASSKEY_OPTIONS_IP cada 15 min:
    # el autollenado pide uno en cada carga del login, así que pasarse no es un fallo y lleva su propio mensaje.
    if sessions.is_ip_locked(ip):
        raise HTTPException(429, LOCKED, headers={'Retry-After': str(sessions.LOCK_SECONDS)})
    if not sessions.take_passkey_options(ip):
        raise HTTPException(429, PASSKEY_OPTIONS_LIMIT, headers={'Retry-After': str(sessions.LOCK_SECONDS)})
    options, challenge = webauthn.authentication_options()
    response.headers.update(NO_STORE)
    return {'options': options, 'login_token': sessions.create_passkey_login(challenge),
            'expires_in_seconds': sessions.PASSKEY_SECONDS}


@router.post('/passkeys/login/verify', summary='Entrar con passkey, paso 2: revisa la firma y crea la sesión')
def passkey_login_verify(body: PasskeyLoginVerifyIn, request: Request, response: Response):
    _passkeys_on()
    ip = client_ip(request)
    if sessions.is_ip_locked(ip):
        raise HTTPException(429, LOCKED, headers={'Retry-After': str(sessions.LOCK_SECONDS)})
    # El reto se gasta antes de todo: cada login_token revisa una sola respuesta.
    challenge = sessions.take_passkey_login(body.login_token)
    if challenge is None:
        raise HTTPException(401, PASSKEY_EXPIRED)
    credential_id = webauthn.credential_id_of(body.credential)
    found = None
    if credential_id:
        with transaction() as conn:
            found = conn.execute('SELECT * FROM passkey_lookup(%s)', (credential_id,)).fetchone()
    if not found:
        sessions.register_ip_fail(ip)
        raise HTTPException(401, PASSKEY_INVALID)
    org, user_id, email = str(found['organization_id']), str(found['user_id']), found['email'].lower()
    if sessions.is_locked(email, ip):
        # Igual que una passkey que no existe (401 y un fallo de la IP): un 429 diría que la credencial es de un correo
        # bloqueado. El motivo queda solo en la bitácora.
        sessions.register_ip_fail(ip)
        return JSONResponse({'detail': PASSKEY_INVALID}, status_code=401,
                            background=BackgroundTask(_audit_passkey_login_failed, org, user_id, ip, 'locked'))
    reason = None
    # El userHandle no entra en la firma: se compara para que la respuesta sea coherente con la credencial. Lo que ata la
    # respuesta a la cuenta es la firma con la llave pública guardada que devolvió passkey_lookup().
    if webauthn.user_handle_of(body.credential) != webauthn.user_handle(user_id):
        reason = 'user_handle'
    else:
        try:
            new_count, backed_up = webauthn.verify_authentication(body.credential, challenge, found['public_key'],
                                                                  found['sign_count'])
        except webauthn.PasskeyError as exc:
            log.info('Entrada con passkey rechazada del usuario %s: %s', user_id, exc)
            reason = 'response'
    if reason:
        sessions.register_fail(email, ip)
        return JSONResponse({'detail': PASSKEY_INVALID}, status_code=401,
                            background=BackgroundTask(_audit_passkey_login_failed, org, user_id, ip, reason))
    with transaction(org) as conn:
        row = conn.execute('SELECT role, email::text FROM users WHERE id = %s AND is_active FOR NO KEY UPDATE',
                           (user_id,)).fetchone()
        if not row:  # se desactivó la cuenta entre la búsqueda y aquí
            reason = 'inactive'
        # Solo si nadie la borró ni la usó con otro contador desde la búsqueda: si no, puede ser una respuesta repetida
        # o un autenticador clonado, y queda en la bitácora.
        elif not conn.execute('UPDATE webauthn_credentials SET sign_count = %s, backed_up = %s, last_used_at = now() '
                              'WHERE id = %s AND user_id = %s AND sign_count = %s',
                              (new_count, backed_up, found['passkey_id'], user_id, found['sign_count'])).rowcount:
            reason = 'sign_count_race'
        else:
            user = _start_session(response, conn, {'id': user_id, 'organization_id': org, 'role': row['role'],
                                                   'email': row['email']}, ip, 'passkey')
    if reason:
        sessions.register_fail(email, ip)
        return JSONResponse({'detail': PASSKEY_INVALID}, status_code=401,
                            background=BackgroundTask(_audit_passkey_login_failed, org, user_id, ip, reason))
    _clear_fails(email)
    return {'user': user}


@router.get('/passkeys', summary='Passkeys de la cuenta de la sesión')
def passkeys_list(response: Response, session: Session = Depends(current_session)):
    with transaction(session.own_org_id) as conn:
        rows = conn.execute('SELECT ' + PASSKEY_COLUMNS + ' FROM webauthn_credentials WHERE user_id = %s '
                            'ORDER BY created_at', (session.user_id,)).fetchall()
    response.headers.update(NO_STORE)
    return {'passkeys': rows, 'available': webauthn.configured(), 'max': MAX_PASSKEYS}


@router.delete('/passkeys/{passkey_id}', status_code=204, summary='Borra una passkey de la cuenta de la sesión')
def passkeys_delete(passkey_id: uuid.UUID, request: Request, session: Session = Depends(current_session)):
    with transaction(session.own_org_id) as conn:
        row = conn.execute('DELETE FROM webauthn_credentials WHERE id = %s AND user_id = %s RETURNING id',
                           (passkey_id, session.user_id)).fetchone()
        if not row:
            raise HTTPException(404, PASSKEY_NOT_FOUND)
        audit(conn, session.own_org_id, 'auth.passkey_deleted', session.user_id, client_ip(request), 'passkey',
              passkey_id, {'reason': 'user'})

"""Sesiones del portal en Valkey. La cookie solo lleva un token aleatorio; en Valkey se
guarda bajo su SHA-256, así que ni quien lea Valkey puede reusar la cookie.

- Inactividad: 15 min (OWASP ASVS V3.3, igual que el aviso del portal).
- Duración máxima: 8 h aunque haya actividad.
- Verificación en dos pasos pendiente: 5 min y 5 intentos.
- Bloqueo por intentos: 5 fallos por correo o 20 por IP en 15 min. Un código equivocado también
  cuenta, y la contraseña correcta no borra los fallos hasta que el código sea correcto.
"""
import hashlib
import json
import secrets
import time
from functools import cache

import redis

from cirdan.config import config

IDLE_SECONDS = 15 * 60
ABSOLUTE_SECONDS = 8 * 60 * 60
MFA_SECONDS = 5 * 60
MFA_MAX_ATTEMPTS = 5
LOCK_SECONDS = 15 * 60
MAX_FAILS_EMAIL = 5
MAX_FAILS_IP = 20
MAX_PASSWORD_FAILS_USER = 5
MAX_PASSWORD_FAILS_IP = 20
TOTP_SETUP_SECONDS = 10 * 60
TOTP_SETUP_MAX_ATTEMPTS = 5


@cache
def _valkey():
    url = config('VALKEY_URL') or 'redis://:%s@%s:%s/0' % (
        config('VALKEY_PASSWORD', ''), config('VALKEY_HOST', '127.0.0.1'), config('VALKEY_PORT', '6379'))
    # Si Valkey no contesta, falla a los 3 s. Con redis 8.1 el tiempo para conectar ya no
    # sale de socket_timeout (serían 5 s), por eso va aparte.
    return redis.Redis.from_url(url, decode_responses=True, socket_timeout=3, socket_connect_timeout=3)


def _digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


# ------------------------------------------------------------------ sesiones

def create(data):
    """Crea una sesión y devuelve el token que va en la cookie."""
    token = secrets.token_urlsafe(32)
    payload = dict(data, created_at=int(time.time()))
    _valkey().set('sess:' + _digest(token), json.dumps(payload), ex=IDLE_SECONDS)
    return token


def get(token):
    """Datos de la sesión, renovando la inactividad; None si no existe, expiró o pasó de 8 h."""
    if not token or len(token) > 100:
        return None
    key = 'sess:' + _digest(token)
    raw = _valkey().get(key)
    if raw is None:
        return None
    data = json.loads(raw)
    if time.time() - data['created_at'] > ABSOLUTE_SECONDS:
        _valkey().delete(key)
        return None
    _valkey().expire(key, IDLE_SECONDS)
    return data


def delete(token):
    if token:
        _valkey().delete('sess:' + _digest(token))


# ------------------------------------------------------------------ verificación en dos pasos pendiente

def create_mfa(data):
    token = secrets.token_urlsafe(32)
    _valkey().set('mfa:' + _digest(token), json.dumps(dict(data, attempts=0)), ex=MFA_SECONDS)
    return token


# Corre entera dentro de Valkey, sin que otra petición se meta entre la lectura y la escritura.
# Si la clave ya no existe no la crea, así que un mfa_token vencido no revive sin vencimiento.
_TAKE_MFA = '''
local raw = redis.call('GET', KEYS[1])
if not raw then return false end
local data = cjson.decode(raw)
data.attempts = data.attempts + 1
if data.attempts >= tonumber(ARGV[1]) then
  redis.call('DEL', KEYS[1])
else
  redis.call('SET', KEYS[1], cjson.encode(data), 'KEEPTTL')
end
return raw
'''


def take_mfa(token):
    """Gasta un intento del mfa_token antes de revisar el código y devuelve sus datos; None si no
    existe o expiró. Con el quinto se borra: aunque lleguen 500 a la vez, solo 5 se revisan."""
    if not token or len(token) > 100:
        return None
    raw = _valkey().eval(_TAKE_MFA, 1, 'mfa:' + _digest(token), MFA_MAX_ATTEMPTS)
    return json.loads(raw) if raw else None


def delete_mfa(token):
    _valkey().delete('mfa:' + _digest(token))


# ------------------------------------------------------------------ bloqueo por intentos

def _email_key(email):
    return 'login:fail:email:' + _digest(email.lower())


def _ip_key(ip):
    return 'login:fail:ip:' + (ip or 'desconocida')


def _count(*keys):
    pipe = _valkey().pipeline()
    for key in keys:
        pipe.incr(key)
        pipe.expire(key, LOCK_SECONDS, nx=True)
    return pipe.execute()[::2]


def is_locked(email, ip):
    fails_email, fails_ip = _valkey().mget(_email_key(email), _ip_key(ip))
    return int(fails_email or 0) >= MAX_FAILS_EMAIL or int(fails_ip or 0) >= MAX_FAILS_IP


def register_fail(email, ip):
    _count(_email_key(email), _ip_key(ip))


def take_mfa_attempt(email, ip):
    """Cuenta el código como fallo del correo antes de revisarlo; False si el correo o la IP ya
    están bloqueados. Contado después, las peticiones en paralelo pasarían todas con el contador en 0.
    Con la IP bloqueada no cuenta para el correo, porque ese código no se revisa."""
    if int(_valkey().get(_ip_key(ip)) or 0) >= MAX_FAILS_IP:
        return False
    fails_email, = _count(_email_key(email))
    return fails_email <= MAX_FAILS_EMAIL


def register_mfa_fail(ip):
    """El código equivocado ya contó para el correo en take_mfa_attempt; aquí cuenta para la IP."""
    _count(_ip_key(ip))


def clear_fails(email):
    _valkey().delete(_email_key(email))


# ------------------------------------------------------------------ cambio de contraseña

def _password_user_key(user_id):
    return 'password:fail:user:' + _digest(str(user_id))


def _password_ip_key(ip):
    return 'password:fail:ip:' + (ip or 'desconocida')


def is_password_locked(user_id, ip):
    fails_user, fails_ip = _valkey().mget(_password_user_key(user_id), _password_ip_key(ip))
    return int(fails_user or 0) >= MAX_PASSWORD_FAILS_USER or int(fails_ip or 0) >= MAX_PASSWORD_FAILS_IP


def register_password_fail(user_id, ip):
    _count(_password_user_key(user_id), _password_ip_key(ip))


def clear_password_fails(user_id):
    _valkey().delete(_password_user_key(user_id))


# ------------------------------------------------------------------ TOTP

def create_totp_secret(user_id):
    """Crea un secreto TOTP y lo guarda de forma segura."""
    secret = secrets.token_urlsafe(10)
    _valkey().set('totp:secret:' + _digest(str(user_id)), secret, ex=TOTP_SETUP_SECONDS)
    return secret


def get_totp_secret(user_id):
    """Devuelve el secreto TOTP guardado."""
    return _valkey().get('totp:secret:' + _digest(str(user_id)))


def delete_totp_secret(user_id):
    """Borra el secreto TOTP guardado."""
    _valkey().delete('totp:secret:' + _digest(str(user_id)))


def verify_totp(token, user_id, secret=None):
    """Verifica un código TOTP contra el secreto guardado."""
    import pyotp
    if secret is None:
        secret = get_totp_secret(user_id)
    return pyotp.TOTP(secret).verify(token)


def generate_totp_uri(user_id, secret, nombre=''):
    """Genera una URI para configurar el TOTP en un cliente."""
    return 'otpauth://totp/%s?secret=%s&issuer=TuApp' % (nombre or user_id, secret)


# ------------------------------------------------------------------ configuración TOTP pendiente

def create_totp_setup(data):
    token = secrets.token_urlsafe(32)
    _valkey().set('totp_setup:' + _digest(token), json.dumps(dict(data, attempts=0)), ex=TOTP_SETUP_SECONDS)
    return token


_TAKE_TOTP_SETUP = '''
local raw = redis.call('GET', KEYS[1])
if not raw then return false end
local data = cjson.decode(raw)
data.attempts = data.attempts + 1
if data.attempts >= tonumber(ARGV[1]) then
  redis.call('DEL', KEYS[1])
else
  redis.call('SET', KEYS[1], cjson.encode(data), 'KEEPTTL')
end
return raw
'''


def take_totp_setup(token):
    if not token or len(token) > 100:
        return None
    raw = _valkey().eval(_TAKE_TOTP_SETUP, 1, 'totp_setup:' + _digest(token), TOTP_SETUP_MAX_ATTEMPTS)
    return json.loads(raw) if raw else None


def delete_totp_setup(token):
    if token:
        _valkey().delete('totp_setup:' + _digest(token))


# ------------------------------------------------------------------ CAPTCHA ALTCHA

def captcha_key():
    """Llave HMAC persistida en Valkey, creada una sola vez."""
    key = 'captcha:hmac:key'
    valor = _valkey().get(key)
    if not valor:
        valor = secrets.token_hex(32)
        actual = _valkey().get(key)
        if not actual:
            _valkey().set(key, valor)
        else:
            valor = actual
    return valor


def register_captcha_challenge(challenge):
    _valkey().set('captcha:challenge:' + hashlib.sha256(challenge.encode()).hexdigest(), '1', ex=MFA_SECONDS * 2)


def consume_captcha_challenge(challenge):
    key = 'captcha:challenge:' + hashlib.sha256(challenge.encode()).hexdigest()
    return bool(_valkey().getdel(key))

"""Sesiones del portal en Valkey. La cookie solo lleva un token aleatorio; en Valkey se
guarda bajo su SHA-256, así que ni quien lea Valkey puede reusar la cookie.

- Inactividad: 15 min (OWASP ASVS V3.3, igual que el aviso del portal).
- Duración máxima: 8 h aunque haya actividad.
- Verificación en dos pasos pendiente: 5 min y 5 intentos.
- Alta de la verificación en dos pasos (RC-154): el secreto nuevo espera aquí 10 min y 5 códigos, cifrado.
- Captcha del login (RC-154): la llave HMAC de los retos y los retos ya usados, hasta que vencen.
- Passkeys (RC-331): el reto de registro (por usuario y amarrado a la sesión que lo pidió) y el de entrada (por un
  token al azar), 5 min y de un solo uso: se leen y se borran en el mismo paso. /passkeys/login/options cuenta
  60 por IP en 15 min, y los fallos de /passkeys/login/verify cuentan para la IP y el correo como en /login.
- Bloqueo por intentos: 5 fallos por correo o 20 por IP en 15 min. Un código equivocado también
  cuenta, y la contraseña correcta no borra los fallos hasta que el código sea correcto. Una IPv6
  cuenta por su red /64, que es lo que suele tener un solo cliente (#49, RC-91).
"""
import base64
import hashlib
import ipaddress
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
MFA_SETUP_SECONDS = 10 * 60
LOCK_SECONDS = 15 * 60
PASSKEY_SECONDS = 5 * 60
MAX_PASSKEY_OPTIONS_IP = 60
MAX_FAILS_EMAIL = 5
MAX_FAILS_IP = 20


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

def _user_sessions_key(user_id):
    return 'sess-user:' + _digest(str(user_id))


def create(data):
    """Crea una sesión y devuelve el token que va en la cookie. La anota también en el índice de sesiones de su
    usuario (RC-154), que vive lo mismo que la más nueva: 8 h desde la última creada."""
    token = secrets.token_urlsafe(32)
    digest = _digest(token)
    payload = dict(data, created_at=int(time.time()))
    pipe = _valkey().pipeline()
    pipe.set('sess:' + digest, json.dumps(payload), ex=IDLE_SECONDS)
    if data.get('user_id'):
        pipe.sadd(_user_sessions_key(data['user_id']), digest)
        pipe.expire(_user_sessions_key(data['user_id']), ABSOLUTE_SECONDS)
    pipe.execute()
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


def limits(created_at=None):
    """Lo que le queda a la sesión, para el aviso del portal (RC-328): la inactividad que renueva cada petición y
    los segundos hasta el tope de 8 h, contados desde que se creó en Valkey. Sin created_at es una sesión nueva."""
    if created_at is None:
        left = ABSOLUTE_SECONDS
    else:
        left = max(0, int(created_at + ABSOLUTE_SECONDS - time.time()))
    return {'idle_timeout_seconds': IDLE_SECONDS, 'absolute_expires_in_seconds': left}


def delete(token):
    if token:
        _valkey().delete('sess:' + _digest(token))


# Corre entera dentro de Valkey: una sesión creada a la vez entra al índice antes (y se borra) o después. Que no
# entre después sin el segundo factor lo asegura el FOR NO KEY UPDATE del login contra el FOR UPDATE del alta.
_DELETE_OTHERS = '''
local keep = ARGV[1]
for _, digest in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  if digest ~= keep then redis.call('DEL', 'sess:' .. digest) end
end
redis.call('DEL', KEYS[1])
if keep ~= '' and redis.call('EXISTS', 'sess:' .. keep) == 1 then
  redis.call('SADD', KEYS[1], keep)
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
end
'''


def delete_others(user_id, keep_token):
    """Cierra todas las sesiones del usuario menos la de `keep_token` (RC-154, al activar la verificación en dos
    pasos). Las sesiones creadas antes de que existiera el índice no están en él y vencen solas en 8 h."""
    keep = _digest(keep_token) if keep_token else ''
    _valkey().eval(_DELETE_OTHERS, 1, _user_sessions_key(user_id), keep, ABSOLUTE_SECONDS)


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


# ------------------------------------------------------------------ alta de la verificación en dos pasos (RC-154)

def _setup_key(user_id):
    return 'mfa:setup:' + _digest(str(user_id))


def create_mfa_setup(user_id, secret_enc):
    """Guarda el secreto pendiente de un alta (ya cifrado, en base64) por MFA_SETUP_SECONDS. Pedir otro QR reemplaza
    al anterior y reinicia sus intentos. En la base no se escribe nada hasta que llega un código válido."""
    _valkey().set(_setup_key(user_id), json.dumps({'secret_enc': secret_enc, 'attempts': 0}), ex=MFA_SETUP_SECONDS)


def take_mfa_setup(user_id):
    """Gasta un intento del alta pendiente antes de revisar el código, como take_mfa(); None si no hay o venció."""
    raw = _valkey().eval(_TAKE_MFA, 1, _setup_key(user_id), MFA_MAX_ATTEMPTS)
    return json.loads(raw) if raw else None


def delete_mfa_setup(user_id):
    _valkey().delete(_setup_key(user_id))


# ------------------------------------------------------------------ captcha del login (RC-154)

def captcha_hmac_key(candidate):
    """La llave HMAC de los retos: la que ya está en Valkey o, si no hay, `candidate`. SET NX GET la deja en un solo
    paso, así que dos procesos que arrancan a la vez terminan con la misma."""
    old = _valkey().set('captcha:hmac', candidate, nx=True, get=True)
    return old or candidate


def spend_captcha(nonce, seconds):
    """Gasta el reto una sola vez: True la primera vez que llega su nonce, False las demás."""
    return bool(_valkey().set('captcha:used:' + _digest(nonce), '1', nx=True, ex=seconds))


# ------------------------------------------------------------------ passkeys (RC-331)

def _passkey_reg_key(user_id):
    return 'webauthn:reg:' + _digest(str(user_id))


def create_passkey_registration(user_id, session_token, challenge):
    """Guarda el reto de un registro de passkey por PASSKEY_SECONDS. Pedir otro reemplaza al anterior. Queda amarrado a
    la sesión que lo pidió: otra sesión de la misma cuenta no lo puede usar."""
    _valkey().set(_passkey_reg_key(user_id), json.dumps({'challenge': base64.b64encode(challenge).decode(),
                                                         'session': _digest(session_token)}), ex=PASSKEY_SECONDS)


def take_passkey_registration(user_id, session_token):
    """El reto del registro, una sola vez (GETDEL); None si no hay, venció o lo pidió otra sesión."""
    raw = _valkey().getdel(_passkey_reg_key(user_id))
    if not raw:
        return None
    data = json.loads(raw)
    if not secrets.compare_digest(data.get('session', ''), _digest(session_token)):
        return None
    return base64.b64decode(data['challenge'])


def create_passkey_login(challenge):
    """Guarda el reto de una entrada con passkey y devuelve el token que el portal manda de vuelta con la respuesta."""
    token = secrets.token_urlsafe(32)
    _valkey().set('webauthn:auth:' + _digest(token), base64.b64encode(challenge).decode(), ex=PASSKEY_SECONDS)
    return token


def take_passkey_login(token):
    """El reto de la entrada, una sola vez (GETDEL): aunque lleguen 100 respuestas a la vez, solo una se revisa."""
    if not token or len(token) > 100:
        return None
    raw = _valkey().getdel('webauthn:auth:' + _digest(token))
    return base64.b64decode(raw) if raw else None


def take_passkey_options(ip):
    """Cuenta una petición de /passkeys/login/options de la IP; False si ya pasó de MAX_PASSKEY_OPTIONS_IP en 15 min."""
    count, = _count('webauthn:opts:ip:' + _ip_bloque(ip))
    return count <= MAX_PASSKEY_OPTIONS_IP


# ------------------------------------------------------------------ bloqueo por intentos

def _email_key(email):
    return 'login:fail:email:' + _digest(email.lower())


def _ip_bloque(ip):
    """La IP con la que cuenta el bloqueo. Una IPv6 cuenta por su /64: quien tiene una red /64 puede estrenar
    dirección en cada intento, y con la dirección completa nunca llegaría a MAX_FAILS_IP. Una IPv4 escrita como
    IPv6 (::ffff:a.b.c.d) cuenta como la IPv4. Lo que no se lee como IP queda tal cual."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip or 'desconocida'
    if addr.version == 6:
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.IPv6Network((int(addr), 64), strict=False))
    return str(addr)


def _ip_key(ip):
    return 'login:fail:ip:' + _ip_bloque(ip)


def _count(*keys):
    pipe = _valkey().pipeline()
    for key in keys:
        pipe.incr(key)
        pipe.expire(key, LOCK_SECONDS, nx=True)
    return pipe.execute()[::2]


def is_locked(email, ip):
    fails_email, fails_ip = _valkey().mget(_email_key(email), _ip_key(ip))
    return int(fails_email or 0) >= MAX_FAILS_EMAIL or int(fails_ip or 0) >= MAX_FAILS_IP


def is_ip_locked(ip):
    """Solo la IP: antes de saber de qué correo es una passkey."""
    return int(_valkey().get(_ip_key(ip)) or 0) >= MAX_FAILS_IP


def register_ip_fail(ip):
    """Un fallo sin correo conocido (una passkey que no existe): cuenta solo para la IP."""
    _count(_ip_key(ip))


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

"""Sesiones del portal en Valkey. La cookie solo lleva un token aleatorio; en Valkey se
guarda bajo su SHA-256, así que ni quien lea Valkey puede reusar la cookie.

- Inactividad: 15 min (OWASP ASVS V3.3, igual que el aviso del portal).
- Duración máxima: 8 h aunque haya actividad.
- Verificación en dos pasos pendiente: 5 min y 5 intentos.
- Alta de la verificación en dos pasos (RC-154): el secreto nuevo espera aquí 10 min y 5 códigos, cifrado.
- Captcha del login (RC-154): la llave HMAC de los retos y los retos ya usados, hasta que vencen.
- Passkeys (RC-331): el reto de registro (por usuario y por la sesión que lo pidió) y el de entrada (por un
  token al azar), 5 min y de un solo uso: se leen y se borran en el mismo paso. /passkeys/login/options cuenta
  300 por IP en 15 min, y los fallos de /passkeys/login/verify cuentan para la IP y el correo como en /login.
- Bloqueo por intentos: 5 fallos por correo o 20 por IP en 15 min. Un código equivocado también
  cuenta, y la contraseña correcta no borra los fallos hasta que el código sea correcto. /login cuenta el
  intento antes de revisar la contraseña, no cuenta nada si ya está bloqueado y lo devuelve si fue correcta (RC-270).
  Una IPv6
  cuenta por su red /64, que es lo que suele tener un solo cliente (#49, RC-91).
- Cambio de contraseña (RC-290): 5 intentos por usuario en 15 min, contados antes de revisar la contraseña actual.
  El quinto fallo cierra la sesión que lo hizo.
- Enlace al correo (#28, RC-63): el token del enlace vive 15 min bajo su SHA-256 y se canjea una sola vez; pedir otro
  anula el anterior. Se piden 3 por correo y 10 por IP en 15 min, y se envían hasta ENLACE_TOPE_DIARIO al día (UTC).
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
MAX_PASSKEY_OPTIONS_IP = 300  # el autollenado pide uno en cada carga del login: alcanza para una oficina tras un NAT
MAX_FAILS_EMAIL = 5
MAX_FAILS_IP = 20
MAX_PASSWORD_ATTEMPTS = 5  # cambio de contraseña: intentos por usuario en LOCK_SECONDS (RC-290)
MAX_PWNED_CHECKS = 10  # consultas a Pwned Passwords por usuario en LOCK_SECONDS (RC-334)
MAX_ASSISTANT_QUESTIONS = 20
ASSISTANT_WINDOW_SECONDS = 24 * 60 * 60
LINK_SECONDS = 15 * 60
MAX_LINKS_EMAIL = 3   # enlaces pedidos por correo en LOCK_SECONDS (#28, RC-63)
MAX_LINKS_IP = 10     # y por IP
LINK_DAY_SECONDS = 48 * 60 * 60  # el contador del día vive dos días: alcanza para cualquier zona y se borra solo


@cache
def _valkey():
    url = config('VALKEY_URL') or 'redis://:%s@%s:%s/0' % (
        config('VALKEY_PASSWORD', ''), config('VALKEY_HOST', '127.0.0.1'), config('VALKEY_PORT', '6379'))
    # Si Valkey no contesta, falla a los 3 s. Con redis 8.1 el tiempo para conectar ya no
    # sale de socket_timeout (serían 5 s), por eso va aparte.
    return redis.Redis.from_url(url, decode_responses=True, socket_timeout=3, socket_connect_timeout=3)


def _digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------- límite del asistente

_TAKE_ASSISTANT_QUESTION = '''
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
if count >= tonumber(ARGV[1]) then return 0 end
count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
return 1
'''


def take_assistant_question(user_id):
    """Reserva una pregunta por usuario en una ventana de 24 h; la llave de Valkey no contiene el ID real."""
    digest = _digest(str(user_id))
    return bool(_valkey().eval(_TAKE_ASSISTANT_QUESTION, 1, 'assistant:questions:' + digest,
                               MAX_ASSISTANT_QUESTIONS, ASSISTANT_WINDOW_SECONDS))


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


SWITCHED, SESSION_GONE, SWITCH_CONFLICT = 'switched', 'gone', 'conflict'

# Corre entera dentro de Valkey: entre leer la empresa activa y escribir la nueva no se mete otro cambio. Si la
# sesión ya no está en la empresa de la que partió la petición, otro cambio llegó antes y este no se aplica.
_SWITCH_ORG = '''
local raw = redis.call('GET', KEYS[1])
if not raw then return 'gone' end
local data = cjson.decode(raw)
if data.org_id ~= ARGV[1] then return 'conflict' end
data.org_id = ARGV[2]
data.role = ARGV[3]
redis.call('SET', KEYS[1], cjson.encode(data), 'KEEPTTL')
return 'switched'
'''


def switch_org(token, expected_org_id, org_id, role):
    """Cambia la empresa activa y el rol de una sesión que ya existe (superadmin, RC-332), solo si sigue en
    `expected_org_id`. Conserva su inactividad, su tope de 8 h y su lugar en el índice del usuario, y una sesión que
    se cerró mientras tanto no revive. Devuelve SWITCHED, SESSION_GONE o SWITCH_CONFLICT (otro cambio ganó)."""
    if not token or len(token) > 100:
        return SESSION_GONE
    return _valkey().eval(_SWITCH_ORG, 1, 'sess:' + _digest(token), str(expected_org_id), str(org_id), role)


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


# ------------------------------------------------------------------ enlace al correo (#28, RC-63)

def _link_user_key(user_id):
    return 'link-user:' + _digest(str(user_id))


# KEYS: el índice de la cuenta (link-user:) y el token nuevo (link:<hash>). ARGV: el hash nuevo, sus datos y los
# segundos. Borra el token anterior de la cuenta y deja el nuevo en un solo paso: dos pedidos a la vez dejan uno solo.
_CREATE_LINK = '''
local anterior = redis.call('GET', KEYS[1])
if anterior then redis.call('DEL', 'link:' .. anterior) end
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
'''
# KEYS: el token (link:<hash>). ARGV: su hash. Lo lee y lo borra en el mismo paso (como GETDEL), y limpia el índice de
# su cuenta solo si sigue apuntando a este token. Dos canjes a la vez: uno lo recibe y el otro ve nil.
_TAKE_LINK = '''
local raw = redis.call('GET', KEYS[1])
if not raw then return false end
redis.call('DEL', KEYS[1])
local data = cjson.decode(raw)
local indice = 'link-user:' .. data.user_key
if redis.call('GET', indice) == ARGV[1] then redis.call('DEL', indice) end
return raw
'''


def create_link(data):
    """Crea el token de un enlace para `data` (user_id, org_id, email) y lo devuelve: 32 bytes al azar. En Valkey solo
    queda su SHA-256, vence en LINK_SECONDS y anula el enlace anterior de la misma cuenta."""
    token = secrets.token_urlsafe(32)
    digest = _digest(token)
    payload = json.dumps(dict(data, user_key=_digest(str(data['user_id']))))
    _valkey().eval(_CREATE_LINK, 2, _link_user_key(data['user_id']), 'link:' + digest, digest, payload, LINK_SECONDS)
    return token


def take_link(token):
    """Los datos del enlace, una sola vez; None si no existe, venció, ya se usó o lo anuló otro más nuevo."""
    if not token or len(token) > 100:
        return None
    digest = _digest(token)
    raw = _valkey().eval(_TAKE_LINK, 1, 'link:' + digest, digest)
    if not raw:
        return None
    data = json.loads(raw)
    data.pop('user_key', None)
    return data


def delete_link(token):
    """Borra el token si el envío falló: un enlace que nunca llegó no debe quedar vivo."""
    _valkey().delete('link:' + _digest(token))


def take_link_request(email, ip):
    """Cuenta un pedido de enlace para el correo y la IP; False si el correo ya pidió MAX_LINKS_EMAIL o la IP
    MAX_LINKS_IP en LOCK_SECONDS, y entonces no cuenta nada. Revisar y contar van en un solo paso, como /login."""
    vence = _valkey().eval(_TAKE, 2, 'link:req:email:' + _digest(email.lower()), 'link:req:ip:' + _ip_bloque(ip),
                           MAX_LINKS_EMAIL, MAX_LINKS_IP, LOCK_SECONDS)
    return bool(vence)


_RESERVE_DAY = '''
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
if n > tonumber(ARGV[1]) then
  redis.call('DECR', KEYS[1])
  return 0
end
return n
'''


def reserve_link_send(tope, dia=None):
    """Reserva un envío del día (UTC) si quedan menos de `tope`; 0 si ya se llegó. Solo cuenta lo que se va a enviar.
    `dia` solo lo pasan las pruebas, para no gastar el contador de hoy."""
    dia = dia or time.strftime('%Y-%m-%d', time.gmtime())
    return int(_valkey().eval(_RESERVE_DAY, 1, 'link:day:' + dia, tope, LINK_DAY_SECONDS))


# ------------------------------------------------------------------ passkeys (RC-331)

def _passkey_reg_key(user_id, session_token):
    # Por usuario y por sesión: otra sesión de la misma cuenta no puede usar ni borrar el reto de esta.
    return 'webauthn:reg:%s:%s' % (_digest(str(user_id)), _digest(session_token))


def password_tag(password_hash):
    """SHA-256 de la huella guardada de la contraseña: cambia cada vez que se cambia la contraseña."""
    return hashlib.sha256(password_hash.encode()).hexdigest()


def create_passkey_registration(user_id, session_token, challenge, tag):
    """Guarda el reto de un registro de passkey por PASSKEY_SECONDS. Pedir otro desde la misma sesión reemplaza al
    anterior. Queda amarrado a la sesión que lo pidió: otra sesión de la misma cuenta no lo puede usar ni borrar.
    Guarda también `tag`, el password_tag de la contraseña con la que se pidió: tras un cambio ya no registra."""
    _valkey().set(_passkey_reg_key(user_id, session_token), base64.b64encode(challenge).decode() + ':' + tag,
                  ex=PASSKEY_SECONDS)


def take_passkey_registration(user_id, session_token):
    """(reto, tag) del registro de esta sesión, una sola vez (GETDEL); None si no hay o venció."""
    if not session_token:
        return None
    raw = _valkey().getdel(_passkey_reg_key(user_id, session_token))
    if not raw or ':' not in raw:
        return None
    challenge, tag = raw.split(':', 1)
    return base64.b64decode(challenge), tag


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


# Los dos scripts corren enteros dentro de Valkey, sin que otra petición entre a la mitad.
# _TAKE: KEYS son el correo y la IP, ARGV sus máximos y los segundos del bloqueo. Si alguno ya llegó a su máximo
# devuelve 0 sin contar nada: un 429 no suma al otro contador, como antes con is_locked. Si no, sube los dos, les pone
# el vencimiento solo si no tenían (EXPIRE NX) y devuelve cuándo vence cada uno, en ms (PEXPIRETIME).
_TAKE = '''
for i, key in ipairs(KEYS) do
  if tonumber(redis.call('GET', key) or '0') >= tonumber(ARGV[i]) then return 0 end
end
local vence = {}
for i, key in ipairs(KEYS) do
  redis.call('INCR', key)
  redis.call('EXPIRE', key, ARGV[3], 'NX')
  vence[i] = redis.call('PEXPIRETIME', key)
end
return vence
'''
# _REFUND: ARGV es lo que devolvió _TAKE. Solo baja el contador que sigue con ese mismo vencimiento, o sea la misma
# ventana de 15 min que subió el intento. Si venció entre los dos pasos (PEXPIRETIME da -2) no lo crea en -1, y si otro
# fallo ya abrió una ventana nueva no se lo come. DECR conserva el vencimiento.
_REFUND = '''
for i, key in ipairs(KEYS) do
  if redis.call('PEXPIRETIME', key) == tonumber(ARGV[i]) and tonumber(redis.call('GET', key) or '0') > 0 then
    redis.call('DECR', key)
  end
end
'''


def take_login_attempt(email, ip):
    """Cuenta el intento de /login para el correo y la IP antes de revisar la contraseña (RC-270). Devuelve el
    comprobante para refund_login_attempt, o None si el correo ya tiene MAX_FAILS_EMAIL o la IP MAX_FAILS_IP, y
    entonces no cuenta nada. Revisar y contar van en un solo script de Valkey, así que aunque lleguen 30 contraseñas a
    la vez cada una ve un número distinto y solo 5 se revisan. Contado después, como antes, todas pasaban con el
    contador en 0, igual que en take_mfa_attempt."""
    vence = _valkey().eval(_TAKE, 2, _email_key(email), _ip_key(ip), MAX_FAILS_EMAIL, MAX_FAILS_IP, LOCK_SECONDS)
    return vence or None


def refund_login_attempt(email, ip, ticket):
    """La contraseña fue correcta: devuelve el intento que contó take_login_attempt, porque un login bueno no es un
    fallo. Para la IP, una oficina tras un NAT no se bloquea con 20 entradas buenas en 15 min. Para el correo, con
    TOTP los 5 intentos siguen siendo para los códigos, y sin TOTP el login borra después los fallos del correo."""
    _valkey().eval(_REFUND, 2, _email_key(email), _ip_key(ip), *ticket)


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
    _valkey().delete(_email_key(email), *(_lock_mark_key(event, 'email', _digest(email.lower()))
                                          for event in LOCK_EVENTS))


# ------------------------------------------------------------------ primer aviso de cada bloqueo (RC-302)

LOCK_EVENTS = ('login', 'mfa')


def _lock_mark_key(event, kind, value):
    # Bajo login:fail: para que las pruebas lo borren con los contadores. No empieza con login:fail:email: ni
    # login:fail:ip:, así que no se confunde con ellos.
    return 'login:fail:aviso:%s:%s:%s' % (event, kind, value)


# KEYS en pares: el contador y su marca. ARGV: el máximo de cada contador y los segundos del bloqueo. Por cada par, si
# el contador ya llegó a su máximo y la marca no existe, la pone con el mismo vencimiento que el contador (PXAT con su
# PEXPIRETIME) y devuelve 1. Así la marca dura lo que dura esa ventana de bloqueo, ni más ni menos, y el siguiente
# bloqueo del mismo correo o IP, en otra ventana, vuelve a avisar. Sin vencimiento (no debería pasar) dura
# LOCK_SECONDS.
_MARK_LOCK = '''
local out = {}
for i = 1, #KEYS, 2 do
  local n = (i + 1) / 2
  out[n] = 0
  if tonumber(redis.call('GET', KEYS[i]) or '0') >= tonumber(ARGV[n]) then
    local vence = redis.call('PEXPIRETIME', KEYS[i])
    local puesta
    if vence > 0 then
      puesta = redis.call('SET', KEYS[i + 1], '1', 'NX', 'PXAT', vence)
    else
      puesta = redis.call('SET', KEYS[i + 1], '1', 'NX', 'EX', ARGV[#ARGV])
    end
    if puesta then out[n] = 1 end
  end
end
return out
'''


def _ip_mark_key(event, ip, org):
    # Con `org` la marca de la IP es de esa empresa: el 429 del MFA ya sabe de qué empresa es la cuenta, y el primero
    # de cada empresa en la ventana deja su auth.mfa_locked en su bitácora, aunque otra ya haya avisado de la misma IP.
    # El 429 del login sale antes de buscar el correo, así que su marca sigue siendo una por IP.
    bloque = _ip_bloque(ip)
    return _lock_mark_key(event, 'ip', bloque if org is None else '%s:%s' % (bloque, org))


def first_lock(event, email, ip, org=None):
    """Dice qué bloqueos son nuevos para `event` ('login' o 'mfa'): una tupla (correo, ip) con True solo la primera vez
    en cada ventana de bloqueo. audit_log no se purga: sin esto, cada 429 de un ataque sería una fila más. Con `org`
    (el MFA), la de la IP es la primera vez para esa empresa."""
    if event not in LOCK_EVENTS:
        raise ValueError(event)
    keys = (_email_key(email), _lock_mark_key(event, 'email', _digest(email.lower())),
            _ip_key(ip), _ip_mark_key(event, ip, org))
    correo, ip_nueva = _valkey().eval(_MARK_LOCK, 4, *keys, MAX_FAILS_EMAIL, MAX_FAILS_IP, LOCK_SECONDS)
    return bool(correo), bool(ip_nueva)


def forget_lock(event, email, ip, por_correo, por_ip, org=None):
    """Quita las marcas que acaba de poner first_lock, cuando el evento no se pudo escribir: así el siguiente 429 de
    esa misma ventana lo vuelve a intentar. `org` es el mismo que recibió first_lock."""
    keys = [_lock_mark_key(event, 'email', _digest(email.lower()))] if por_correo else []
    if por_ip:
        keys.append(_ip_mark_key(event, ip, org))
    if keys:
        _valkey().delete(*keys)


# ------------------------------------------------------------------ cambio de contraseña (RC-290)

def _password_key(user_id):
    return 'pw:fail:user:' + _digest(str(user_id))


def take_password_attempt(user_id):
    """Cuenta el intento de cambio de contraseña del usuario antes de revisar la contraseña actual y devuelve su
    número: 1 a MAX_PASSWORD_ATTEMPTS se revisan, uno mayor ya no. Es un contador aparte del login, para que quien tiene
    una cookie robada no bloquee el inicio de sesión del dueño. Contado después, las peticiones en paralelo pasarían
    todas con el contador en 0, como en take_mfa_attempt."""
    attempt, = _count(_password_key(user_id))
    return attempt


def clear_password_attempts(user_id):
    _valkey().delete(_password_key(user_id))


def take_pwned_check(user_id):
    """Cuenta una consulta a Pwned Passwords del usuario y devuelve su número: 1 a MAX_PWNED_CHECKS salen a la API, uno
    mayor se revisa solo con la lista local (RC-334). Va antes de take_password_attempt, que no gasta, así que sin este
    tope una sesión podría mandar consultas a la API sin límite desde la IP de la VM. No se borra al cambiar la
    contraseña: es un tope de consultas, no de fallos."""
    check, = _count('pw:pwned:user:' + _digest(str(user_id)))
    return check

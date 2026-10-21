"""Sesiones del portal en Valkey. La cookie solo lleva un token aleatorio; en Valkey se
guarda bajo su SHA-256, así que ni quien lea Valkey puede reusar la cookie.

- Inactividad: 15 min (OWASP ASVS V3.3, igual que el aviso del portal).
- Duración máxima: 8 h aunque haya actividad.
- Verificación en dos pasos pendiente: 5 min y 5 intentos.
- Bloqueo por intentos: 5 fallos por correo o 20 por IP en 15 min.
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


def get_mfa(token):
    if not token or len(token) > 100:
        return None
    raw = _valkey().get('mfa:' + _digest(token))
    return json.loads(raw) if raw else None


def fail_mfa(token, data):
    """Cuenta un código equivocado; al quinto se descarta y hay que iniciar sesión otra vez."""
    key = 'mfa:' + _digest(token)
    data['attempts'] += 1
    if data['attempts'] >= MFA_MAX_ATTEMPTS:
        _valkey().delete(key)
    else:
        _valkey().set(key, json.dumps(data), keepttl=True)


def delete_mfa(token):
    _valkey().delete('mfa:' + _digest(token))


# ------------------------------------------------------------------ bloqueo por intentos

def _fail_keys(email, ip):
    return 'login:fail:email:' + _digest(email.lower()), 'login:fail:ip:' + (ip or 'desconocida')


def is_locked(email, ip):
    email_key, ip_key = _fail_keys(email, ip)
    fails_email, fails_ip = _valkey().mget(email_key, ip_key)
    return int(fails_email or 0) >= MAX_FAILS_EMAIL or int(fails_ip or 0) >= MAX_FAILS_IP


def register_fail(email, ip):
    pipe = _valkey().pipeline()
    for key in _fail_keys(email, ip):
        pipe.incr(key)
        pipe.expire(key, LOCK_SECONDS, nx=True)
    pipe.execute()


def clear_fails(email):
    _valkey().delete(_fail_keys(email, None)[0])

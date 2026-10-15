"""Ayuda para las pruebas que entran a la API con sesión (biblioteca estándar, sin paquetes).

Inicia sesión como una cuenta de demo (cirdan/auth/demo.py) con contraseña y código TOTP, y
devuelve un cliente con su cookie. Necesita `docker compose up` con DEMO_ACCOUNTS=true.
"""
import ast
import base64
import hashlib
import hmac
import http.cookiejar
import json
import struct
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = 'http://127.0.0.1:8000'
AUTH = BASE + '/api/v1/auth'
PASSWORD = 'Lowtide-Demo-2026'
STEP = 30


def _demo_secrets():
    """Lee los secretos de cirdan/auth/demo.py sin importarlo (no requiere pyotp)."""
    tree = ast.parse((Path(__file__).resolve().parents[1] / 'cirdan' / 'auth' / 'demo.py').read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', None) == 'CUENTAS':
            return {k.value: v.elts[2].value for k, v in zip(node.value.keys, node.value.values)}
    raise RuntimeError('No se encontró CUENTAS en cirdan/auth/demo.py')


SECRETS = _demo_secrets()
_last_step = {}


def totp(secret, step):
    """Código TOTP de 6 dígitos (RFC 6238, HMAC-SHA1) para un paso de 30 s."""
    key = base64.b32decode(secret)
    digest = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return '%06d' % ((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000)


def next_code(email):
    """Un código que la API todavía no ha visto para esa cuenta (no se puede reusar un código)."""
    current = int(time.time() // STEP)
    step = current if email not in _last_step else _last_step[email] + 1
    while step > int(time.time() // STEP) + 1:  # la API acepta hasta un paso adelante
        time.sleep(1)
    _last_step[email] = step
    return totp(SECRETS[email], step)


def reset():
    """Deja las cuentas listas para la prueba: sin último código usado ni intentos fallidos."""
    subprocess.run(['docker', 'exec', 'cirdan-pg16', 'psql', '-U', 'postgres', '-d', 'cirdan', '-q', '-c',
                    'UPDATE users SET last_totp_step = NULL'], check=True, capture_output=True)
    subprocess.run(['docker', 'exec', 'cirdan-valkey', 'sh', '-c',
                    'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning --scan --pattern "login:fail:*" '
                    '| xargs -r valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning del'], check=True, capture_output=True)
    _last_step.clear()


class Client:
    """Cliente HTTP con su propia cookie de sesión."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, method, url, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url if url.startswith('http') else BASE + url, data=data, method=method,
                                     headers={'Content-Type': 'application/json', **(headers or {})})
        try:
            with self.opener.open(req, timeout=10) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            return e.code, json.loads(raw) if raw else None

    def get(self, url, headers=None):
        return self.request('GET', url, headers=headers)

    def post(self, url, body=None, headers=None):
        return self.request('POST', url, body, headers)

    def cookie(self):
        return next((c for c in self.jar if c.name == 'lt_session'), None)


def login(email):
    """Cliente con sesión iniciada (contraseña y código TOTP)."""
    client = Client()
    code, body = client.post(AUTH + '/login', {'email': email, 'password': PASSWORD})
    assert code == 200 and body['mfa_required'], (code, body)
    code, body = client.post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': next_code(email)})
    assert code == 200, (code, body)
    return client

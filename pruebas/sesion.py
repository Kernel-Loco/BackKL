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
import os
import struct
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from pruebas.pila import exigir_desechable

BASE = os.environ.get('CIRDAN_TEST_BASE', 'http://127.0.0.1:8000')
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


def psql(sql):
    """Corre una sentencia en la base como postgres, fuera de la API."""
    exigir_desechable()
    subprocess.run(['docker', 'exec', os.environ.get('CIRDAN_TEST_DB_CONTAINER', 'cirdan-pg16'),
                    'psql', '-U', 'postgres', '-d', 'cirdan', '-q', '-c', sql],
                   check=True, capture_output=True)


def reset():
    """Deja las cuentas listas para la prueba: sin último código usado ni intentos fallidos, del login ni del cambio de
    contraseña (pw:fail:*, RC-290)."""
    psql('UPDATE users SET last_totp_step = NULL')
    exigir_desechable()
    subprocess.run(['docker', 'exec', os.environ.get('CIRDAN_TEST_VALKEY', 'cirdan-valkey'), 'sh', '-c',
                    'for p in "login:fail:*" "pw:fail:*"; do '
                    'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning --scan --pattern "$p" '
                    '| xargs -r valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning del; done'],
                   check=True, capture_output=True)
    _last_step.clear()


def valkey(*argumentos):
    """Corre valkey-cli en el contenedor de Valkey y da su salida, una línea por valor."""
    exigir_desechable()
    r = subprocess.run(['docker', 'exec', os.environ.get('CIRDAN_TEST_VALKEY', 'cirdan-valkey'), 'sh', '-c',
                        'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning "$@"', 'sh', *argumentos],
                       check=True, capture_output=True, text=True)
    return r.stdout.splitlines()


def esquema():
    """El esquema OpenAPI de la API que corre, con app.openapi() dentro de su contenedor y con su mismo entorno.
    /openapi.json no existe por omisión (API_DOCS, RC-303), así que no se pide por HTTP."""
    exigir_desechable()
    r = subprocess.run(['docker', 'exec', os.environ.get('CIRDAN_TEST_API_CONTAINER', 'cirdan-api'), 'python', '-c',
                        'import json; from cirdan.api.main import app; print(json.dumps(app.openapi()))'],
                       check=True, capture_output=True, text=True, encoding='utf-8')
    return json.loads(r.stdout.strip().splitlines()[-1])


def en_api(codigo):
    """Corre código de Python dentro del contenedor de la API, con su mismo entorno, y da la última línea que imprime."""
    exigir_desechable()
    contenedor = os.environ.get('CIRDAN_TEST_API_CONTAINER', 'cirdan-api')
    r = subprocess.run(['docker', 'exec', contenedor, 'python', '-c', codigo],
                       check=True, capture_output=True, text=True, encoding='utf-8')
    return r.stdout.strip().splitlines()[-1]


def api_logs():
    """El log del contenedor de la API (stdout y stderr juntos), para buscar las líneas que no van a la base."""
    exigir_desechable()
    contenedor = os.environ.get('CIRDAN_TEST_API_CONTAINER', 'cirdan-api')
    r = subprocess.run(['docker', 'logs', contenedor], check=True, capture_output=True, text=True, encoding='utf-8',
                       errors='replace')
    return r.stdout + r.stderr


class Client:
    """Cliente HTTP con su propia cookie de sesión."""

    def __init__(self):
        exigir_desechable()
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


def solve_captcha(challenge):
    """Resuelve un reto ALTCHA de GET /auth/captcha como el widget del portal (PBKDF2-SHA256, contador uint32 al final
    del nonce) y devuelve el campo `captcha` de /login. Tarda alrededor de medio segundo."""
    params = challenge['parameters']
    nonce, salt = bytes.fromhex(params['nonce']), bytes.fromhex(params['salt'])
    counter = 0
    while True:
        key = hashlib.pbkdf2_hmac('sha256', nonce + struct.pack('>I', counter), salt, params['cost'], params['keyLength'])
        if key.hex().startswith(params['keyPrefix']):
            break
        counter += 1
    payload = {'challenge': {'parameters': params, 'signature': challenge['signature']},
               'solution': {'counter': counter, 'derivedKey': key.hex()}}
    return base64.b64encode(json.dumps(payload).encode()).decode()


def captcha(client):
    """Un captcha resuelto y sin usar, pedido con el cliente."""
    code, challenge = client.get(AUTH + '/captcha')
    assert code == 200, (code, challenge)
    return solve_captcha(challenge)


def post_login(client, email, password, headers=None):
    """POST /auth/login con un captcha resuelto, como el portal. Devuelve (código, cuerpo)."""
    return client.post(AUTH + '/login', {'email': email, 'password': password, 'captcha': captcha(client)}, headers)


def login(email):
    """Cliente con sesión iniciada (captcha, contraseña y código TOTP)."""
    client = Client()
    code, body = post_login(client, email, PASSWORD)
    assert code == 200 and body['mfa_required'], (code, body)
    code, body = client.post(AUTH + '/mfa/verify', {'mfa_token': body['mfa_token'], 'code': next_code(email)})
    assert code == 200, (code, body)
    return client

"""Verificación en dos pasos con TOTP (RFC 6238, códigos de 6 dígitos cada 30 s).

El secreto se guarda cifrado con AES-256-GCM en `users.totp_secret_enc`; la llave vive fuera de
la base. `users.last_totp_step` impide usar dos veces el mismo código. La llave sale de una de dos
variables, nunca de las dos:
- `TOTP_KEY_VAULT_SECRET_URL`: en la VM, el secreto de Azure Key Vault que se lee con la identidad
  administrada (`cirdan/auth/keyvault.py`, docs/despliegue.md). Se lee una vez por proceso y queda
  solo en memoria.
- `TOTP_ENCRYPTION_KEY`: la llave misma, en el `.env` de desarrollo, del CI y del plan B.
"""
import base64
import binascii
import hmac
import os
import re
import threading
import time

import pyotp
import segno
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cirdan.auth import keyvault
from cirdan.config import config

STEP_SECONDS = 30
VALID_WINDOW = 1  # acepta el código anterior y el siguiente por desfase de reloj
# Solo 0 a 9. \d y str.isdigit() aceptan dígitos Unicode, como '١٢٣٤٥٦' o los de ancho completo, y luego
# hmac.compare_digest lanza TypeError con texto no ASCII: un 500 sin bitácora ni fallo de la IP (RC-315).
CODE_PATTERN = r'^[0-9]{6}$'

_llave_vault = None
_candado = threading.Lock()


def _decodificar(valor, origen):
    try:
        key = base64.urlsafe_b64decode(valor)
    except (binascii.Error, ValueError):
        key = b''
    if len(key) != 32:
        raise RuntimeError('%s debe ser de 32 bytes en base64 url-safe' % origen)
    return key


def _variables():
    """(url, llave directa), con una sola de las dos puesta, o RuntimeError. Vacía cuenta como sin poner."""
    url = config('TOTP_KEY_VAULT_SECRET_URL')
    directa = config('TOTP_ENCRYPTION_KEY')
    if url and directa:
        raise RuntimeError('TOTP_KEY_VAULT_SECRET_URL y TOTP_ENCRYPTION_KEY están puestas: con Key Vault, '
                           'quita TOTP_ENCRYPTION_KEY del .env')
    if not url and not directa:
        raise RuntimeError('Falta TOTP_ENCRYPTION_KEY o TOTP_KEY_VAULT_SECRET_URL: copia .env.example como .env y '
                           'llena sus valores')
    return url, directa


def revisar_variables():
    """Sin red ni Key Vault: que venga una sola de las dos variables. La usa el script de demo, que corre antes que la
    API, para que `docker compose up` falle con este mensaje en vez de dejar la API reiniciándose."""
    _variables()


def _key():
    url, directa = _variables()
    if directa:
        return _decodificar(directa, 'TOTP_ENCRYPTION_KEY')
    global _llave_vault
    with _candado:
        if _llave_vault is None or _llave_vault[0] != url:
            _llave_vault = (url, _decodificar(keyvault.leer_secreto(url),
                                                'El secreto de Key Vault de TOTP_KEY_VAULT_SECRET_URL'))
        return _llave_vault[1]


def comprobar_llave():
    """Al arrancar la API: sin llave válida no arranca, en vez de fallar en el primer inicio de sesión con MFA.
    Devuelve la llave, para que cirdan/auth/passwords.py revise que la de las huellas sea otra (RC-330)."""
    return _key()


def encrypt_secret(secret, user_id):
    """Cifra el secreto base32; el id del usuario va como dato asociado (no se puede mover a otro usuario)."""
    nonce = os.urandom(12)
    return nonce + AESGCM(_key()).encrypt(nonce, secret.encode(), str(user_id).encode())


def decrypt_secret(blob, user_id):
    if isinstance(blob, memoryview):
        blob = blob.tobytes()
    elif isinstance(blob, str):
        text = blob.strip()
        if text.startswith('\\x'):
            blob = bytes.fromhex(text[2:])
        else:
            # Compatibilidad con datos legados serializados como base64.
            blob = base64.b64decode(text)
    else:
        blob = bytes(blob)
    return AESGCM(_key()).decrypt(blob[:12], blob[12:], str(user_id).encode()).decode()


ISSUER = 'LowTide'


def new_secret():
    """Secreto nuevo de 160 bits en base32 (el tamaño que recomienda el RFC 4226 para HMAC-SHA1)."""
    return pyotp.random_base32(32)


def provisioning_uri(secret, email):
    """URI otpauth://totp/ que leen las apps autenticadoras: SHA1, 6 dígitos y 30 s, lo mismo que verify_code."""
    return pyotp.TOTP(secret, interval=STEP_SECONDS).provisioning_uri(name=email, issuer_name=ISSUER)


def qr_svg_data_uri(uri):
    """El QR de la URI como imagen SVG en un data: URI. Se dibuja aquí para que el secreto no pase por
    ningún servicio ni paquete de terceros en el navegador."""
    return segno.make(uri, error='m').svg_data_uri(scale=6, border=4, dark='#000', light='#fff')


def verify_code(secret, code, last_step=None, now=None):
    """Paso de tiempo del código si es válido y no se ha usado; si no, None."""
    if not (isinstance(code, str) and re.fullmatch(CODE_PATTERN, code)):
        return None
    totp = pyotp.TOTP(secret, interval=STEP_SECONDS)
    current = int((now or time.time()) // STEP_SECONDS)
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None

"""Verificación en dos pasos con TOTP (RFC 6238, códigos de 6 dígitos cada 30 s).

El secreto se guarda cifrado con AES-256-GCM en `users.totp_secret_enc`; la llave vive en
`TOTP_ENCRYPTION_KEY` (fuera de la base). `users.last_totp_step` impide usar dos veces el
mismo código.
"""
import base64
import hmac
import os
import time

import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cirdan.config import required

STEP_SECONDS = 30
VALID_WINDOW = 1  # acepta el código anterior y el siguiente por desfase de reloj


def _key():
    key = base64.urlsafe_b64decode(required('TOTP_ENCRYPTION_KEY'))
    if len(key) != 32:
        raise RuntimeError('TOTP_ENCRYPTION_KEY debe ser de 32 bytes en base64 url-safe')
    return key


def encrypt_secret(secret, user_id):
    """Cifra el secreto base32; el id del usuario va como dato asociado (no se puede mover a otro usuario)."""
    nonce = os.urandom(12)
    return nonce + AESGCM(_key()).encrypt(nonce, secret.encode(), str(user_id).encode())


def decrypt_secret(blob, user_id):
    blob = bytes(blob)
    return AESGCM(_key()).decrypt(blob[:12], blob[12:], str(user_id).encode()).decode()


def verify_code(secret, code, last_step=None, now=None):
    """Paso de tiempo del código si es válido y no se ha usado; si no, None."""
    if not (isinstance(code, str) and len(code) == 6 and code.isdigit()):
        return None
    totp = pyotp.TOTP(secret, interval=STEP_SECONDS)
    current = int((now or time.time()) // STEP_SECONDS)
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None

"""Verificación en dos pasos con TOTP (RFC 6238, códigos de 6 dígitos cada 30 s).

El secreto se guarda cifrado con AES-256-GCM en `users.totp_secret_enc`; la llave vive fuera de
la base. `users.last_totp_step` impide usar dos veces el mismo código. La llave sale de una de dos
variables, nunca de las dos:
- `TOTP_KEY_VAULT_SECRET_URL`: en la VM, el secreto de Azure Key Vault que se lee con la identidad
  administrada (`cirdan/auth/keyvault.py`, docs/despliegue.md). Se lee una vez por proceso y queda
  solo en memoria.
- `TOTP_ENCRYPTION_KEY`: la llave misma, en el `.env` de desarrollo, del CI y del plan B.

Para rotarla (RC-295, docs/despliegue.md), la de antes va mientras tanto en `TOTP_PREVIOUS_KEY_VAULT_SECRET_URL` o en
`TOTP_PREVIOUS_ENCRYPTION_KEY`, una de las dos y opcional. Un secreto se prueba con la actual y luego con la anterior.
El que abre con la anterior se vuelve a cifrar con la actual tras el primer código bueno (cirdan/auth/routes.py), y
`python -m cirdan.auth.contar_totp` cuenta los que siguen con ella. El formato guardado no cambia: sin versión de llave.
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
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cirdan.auth import keyvault
from cirdan.config import config

STEP_SECONDS = 30
VALID_WINDOW = 1  # acepta el código anterior y el siguiente por desfase de reloj
# Solo 0 a 9. \d y str.isdigit() aceptan dígitos Unicode, como '١٢٣٤٥٦' o los de ancho completo, y luego
# hmac.compare_digest lanza TypeError con texto no ASCII: un 500 sin bitácora ni fallo de la IP (RC-315).
CODE_PATTERN = r'^[0-9]{6}$'

VARIABLE_LLAVE_ANTERIOR = 'TOTP_PREVIOUS_ENCRYPTION_KEY'
VARIABLE_URL_ANTERIOR = 'TOTP_PREVIOUS_KEY_VAULT_SECRET_URL'

_llave_vault = None  # (url, llave) de TOTP_KEY_VAULT_SECRET_URL
_llave_vault_anterior = None  # lo mismo para TOTP_PREVIOUS_KEY_VAULT_SECRET_URL
_candado = threading.Lock()


class LlaveNoAbre(Exception):
    """Ni la llave actual ni la anterior abren el secreto: se cifró con otra llave o el dato está dañado."""


def _decodificar(valor, origen):
    try:
        key = base64.urlsafe_b64decode(valor)
    except (binascii.Error, ValueError):
        key = b''
    if len(key) != 32:
        raise RuntimeError('%s debe ser de 32 bytes en base64 url-safe' % origen)
    return key


def _una(variable_url, variable_llave, obligatoria):
    """(url, llave directa) de un par de variables, con una sola puesta, o RuntimeError. Vacía cuenta como sin poner.
    Si no es obligatoria y no viene ninguna, (None, None)."""
    url = config(variable_url)
    directa = config(variable_llave)
    if url and directa:
        raise RuntimeError('%s y %s están puestas: con Key Vault, quita %s del .env'
                           % (variable_url, variable_llave, variable_llave))
    if not url and not directa:
        if obligatoria:
            raise RuntimeError('Falta %s o %s: copia .env.example como .env y llena sus valores'
                               % (variable_llave, variable_url))
        return None, None
    return url, directa


def _variables():
    """(url, llave directa) de la actual, con una sola de las dos puesta, o RuntimeError."""
    return _una('TOTP_KEY_VAULT_SECRET_URL', 'TOTP_ENCRYPTION_KEY', True)


def _variables_anterior():
    """(url, llave directa) de la anterior, (None, None) si no está puesta, o RuntimeError. Sin red: una llave directa
    tiene que ser de 32 bytes y otra que la actual directa, y una URL otra que la actual (RC-295)."""
    url, directa = _una(VARIABLE_URL_ANTERIOR, VARIABLE_LLAVE_ANTERIOR, False)
    url_actual, directa_actual = _variables()
    if directa:
        llave = _decodificar(directa, VARIABLE_LLAVE_ANTERIOR)
        if directa_actual and hmac.compare_digest(llave, _decodificar(directa_actual, 'TOTP_ENCRYPTION_KEY')):
            raise RuntimeError('%s es la misma llave que TOTP_ENCRYPTION_KEY: pon ahí la de antes de rotar'
                               % VARIABLE_LLAVE_ANTERIOR)
    elif url and url_actual and url.strip().lower() == url_actual.strip().lower():
        raise RuntimeError('%s es la misma URL que TOTP_KEY_VAULT_SECRET_URL: pon ahí la de antes de rotar'
                           % VARIABLE_URL_ANTERIOR)
    return url, directa


def revisar_variables():
    """Sin red ni Key Vault: que venga una sola de las dos variables de la actual y, si está puesta, una sola de la
    anterior. La usa el script de demo, que corre antes que la API, para que `docker compose up` falle con este mensaje
    en vez de dejar la API reiniciándose."""
    _variables()
    _variables_anterior()


def _de_key_vault(cache_nombre, url, variable):
    with _candado:
        guardada = globals()[cache_nombre]
        if guardada is None or guardada[0] != url:
            guardada = (url, _decodificar(keyvault.leer_secreto(url, variable=variable),
                                          'El secreto de Key Vault de ' + variable))
            globals()[cache_nombre] = guardada
        return guardada[1]


def _key():
    url, directa = _variables()
    if directa:
        return _decodificar(directa, 'TOTP_ENCRYPTION_KEY')
    return _de_key_vault('_llave_vault', url, 'TOTP_KEY_VAULT_SECRET_URL')


def _llave_anterior():
    """Los bytes de la llave anterior, o None si no está puesta."""
    url, directa = _variables_anterior()
    if directa:
        return _decodificar(directa, VARIABLE_LLAVE_ANTERIOR)
    if url:
        return _de_key_vault('_llave_vault_anterior', url, VARIABLE_URL_ANTERIOR)
    return None


def comprobar_llave():
    """Al arrancar la API: sin llave válida no arranca, en vez de fallar en el primer inicio de sesión con MFA. Con la
    anterior puesta, también la lee, y no arranca si es la misma que la actual, aunque una venga del .env y la otra de
    Key Vault. Devuelve la llave actual, para que cirdan/auth/passwords.py revise que la de las huellas sea otra
    (RC-330)."""
    key = _key()
    anterior = _llave_anterior()
    if anterior is not None and hmac.compare_digest(anterior, key):
        variable = VARIABLE_URL_ANTERIOR if _variables_anterior()[0] else VARIABLE_LLAVE_ANTERIOR
        raise RuntimeError('%s da la misma llave que la actual: pon ahí la de antes de rotar' % variable)
    return key


def encrypt_secret(secret, user_id):
    """Cifra el secreto base32 con la llave actual; el id del usuario va como dato asociado (no se puede mover a otro
    usuario)."""
    nonce = os.urandom(12)
    return nonce + AESGCM(_key()).encrypt(nonce, secret.encode(), str(user_id).encode())


def _a_bytes(blob):
    if isinstance(blob, memoryview):
        return blob.tobytes()
    if isinstance(blob, str):
        text = blob.strip()
        if text.startswith('\\x'):
            return bytes.fromhex(text[2:])
        # Compatibilidad con datos legados serializados como base64.
        return base64.b64decode(text)
    return bytes(blob)


def descifrar(blob, user_id):
    """(secreto, con_anterior): el secreto base32 y True si solo abrió con la llave anterior. LlaveNoAbre si no abre
    con ninguna o el dato no tiene la forma nonce + cifrado + tag. Nunca InvalidTag: sin esto /mfa/verify daba 500
    a todo el que tuviera MFA después de cambiar la llave (RC-295)."""
    try:
        blob = _a_bytes(blob)
    except (binascii.Error, ValueError, TypeError):
        raise LlaveNoAbre() from None
    if len(blob) < 12 + 16:
        raise LlaveNoAbre()
    aad = str(user_id).encode()
    for llave, con_anterior in ((_key(), False), (_llave_anterior(), True)):
        if llave is None:
            continue
        try:
            claro = AESGCM(llave).decrypt(blob[:12], blob[12:], aad)
        except InvalidTag:
            continue
        try:
            return claro.decode('ascii'), con_anterior
        except UnicodeDecodeError:
            raise LlaveNoAbre() from None
    raise LlaveNoAbre()


def decrypt_secret(blob, user_id):
    """El secreto base32, con la actual o la anterior. LlaveNoAbre si ninguna lo abre."""
    return descifrar(blob, user_id)[0]


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

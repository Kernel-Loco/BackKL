"""Almacenamiento cifrado de cartas en un volumen privado."""
import base64
import binascii
import hashlib
import hmac
import os
import threading
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cirdan.auth import keyvault, passwords, totp
from cirdan.config import config

_lock = threading.Lock()
_vault_key = None


def habilitado():
    # Hasta que exista el respaldo, no se acepta alta con cookies de producción.
    return config('CARTA_ALTA_ENABLED', 'false').lower() == 'true' and config('COOKIE_SECURE', 'false').lower() != 'true'


def _key():
    global _vault_key
    url = config('CARTA_KEY_VAULT_SECRET_URL')
    direct = config('CARTA_ENCRYPTION_KEY')
    if bool(url) == bool(direct):
        raise RuntimeError('Configura exactamente una llave de cartas: CARTA_ENCRYPTION_KEY o CARTA_KEY_VAULT_SECRET_URL.')
    if url:
        with _lock:
            if _vault_key is None or _vault_key[0] != url:
                _vault_key = (url, keyvault.leer_secreto(url, variable='CARTA_KEY_VAULT_SECRET_URL'))
            value = _vault_key[1]
    else:
        value = direct
    try:
        key = base64.b64decode(value.encode('ascii'), altchars=b'-_', validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error):
        raise RuntimeError('La llave de cartas debe ser de 32 bytes en base64 url-safe.') from None
    if len(key) != 32:
        raise RuntimeError('La llave de cartas debe ser de 32 bytes en base64 url-safe.')
    if any(hmac.compare_digest(key, other) for other in (totp.comprobar_llave(), passwords._key())):
        raise RuntimeError('La llave de cartas debe ser distinta de las llaves de MFA y contraseñas.')
    return key


def guardar(pdf, org_id, domain_id):
    """Escribe una carta cifrada; la clave devuelta es opaca y la huella corresponde al PDF original."""
    location = config('CARTA_STORAGE_DIR')
    if not location or not Path(location).is_absolute():
        raise RuntimeError('CARTA_STORAGE_DIR debe ser una ruta absoluta a un volumen privado persistente.')
    directory = Path(location)
    if not directory.is_dir():
        raise RuntimeError('El volumen de cartas no existe o no es un directorio.')
    key = _key()
    filename = uuid.uuid4().hex + '.lt1'
    nonce = os.urandom(12)
    associated = ('%s:%s:%s' % (org_id, domain_id, filename)).encode('utf-8')
    ciphertext = b'LT1' + nonce + AESGCM(key).encrypt(nonce, pdf, associated)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(directory / filename, flags, 0o600)
    with os.fdopen(fd, 'wb') as file:
        file.write(ciphertext)
        file.flush()
        os.fsync(file.fileno())
    dir_fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return filename, hashlib.sha256(pdf).digest()

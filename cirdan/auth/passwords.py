"""Contraseñas con argon2id (OWASP ASVS V2.4). Nunca se guardan ni se registran en claro.

La huella argon2id (cadena PHC) se guarda cifrada con AES-256-GCM y una llave que vive fuera de la base (pepper,
RC-330): con un volcado de la base no se pueden probar contraseñas fuera de línea. El id del usuario va como dato
asociado, así que la huella de una cuenta copiada a otra no abre. Se cifra en vez de pasar la contraseña por un HMAC
antes de argon2id porque así la llave se podrá rotar sin que nadie rehaga su contraseña (OWASP Password Storage Cheat
Sheet). La herramienta para rotarla todavía no existe. Formato guardado: 'lt1$' + base64 url-safe de nonce (12 bytes)
+ cifrado. El '1' es la versión de la llave.

Una huella vieja sin cifrar ('$argon2id$...') todavía entra, y `needs_rehash` hace que el login la guarde cifrada en
ese mismo inicio de sesión (cirdan/auth/routes.py). El hash de relleno de las semillas y de demo.py tiene esa forma
pero no es verificable, así que sigue sin abrir nada.

La llave sale de una de dos variables, nunca de las dos, como la del MFA (cirdan/auth/totp.py):
- `PASSWORD_HASH_KEY_VAULT_SECRET_URL`: en la VM, el secreto de Azure Key Vault que se lee con la identidad
  administrada (cirdan/auth/keyvault.py, docs/despliegue.md). Se lee una vez por proceso y queda solo en memoria.
- `PASSWORD_HASH_ENCRYPTION_KEY`: la llave misma, en el `.env` de desarrollo, del CI y del plan B.
Es otra llave que la del MFA, para no amarrar sus rotaciones. Se comparan los bytes de las dos: `_variables` cuando las
dos van en el .env y `comprobar_llave`, al arrancar la API, en todos los casos.
"""
import base64
import binascii
import hmac
import os
import threading
import urllib.parse
import uuid

from argon2 import PasswordHasher, profiles
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cirdan.auth import keyvault
from cirdan.config import config

MIN_LENGTH = 12   # misma política que el portal (src/lib/validation.ts)
MAX_LENGTH = 128

PREFIJO = 'lt1$'
VIEJA = '$argon2id$'
VARIABLE_URL = 'PASSWORD_HASH_KEY_VAULT_SECRET_URL'
VARIABLE_LLAVE = 'PASSWORD_HASH_ENCRYPTION_KEY'

# Fijos: t=3, m=64 MiB, p=4, los mismos que daba PasswordHasher() de argon2-cffi 25.1.0. Así una versión nueva de la
# librería no los cambia sin que nadie lo note (RFC 9106, segunda recomendación).
PARAMETROS = profiles.RFC_9106_LOW_MEMORY
_hasher = PasswordHasher.from_parameters(PARAMETROS)

# Relleno: con un correo que no existe se verifica contra una huella cifrada de esta contraseña, para que la respuesta
# tarde lo mismo que con una contraseña equivocada (descifrar y argon2id) y no se puedan adivinar correos.
_RELLENO = 'lowtide-relleno-que-nunca-coincide'
_ID_RELLENO = '00000000-0000-4000-8000-000000000000'

_llave_vault = None
_relleno = None  # (llave, huella cifrada del relleno)
_phc_relleno = None  # cadena PHC del relleno, sin cifrar: no depende de la llave
_candado = threading.Lock()


def _decodificar(valor, origen):
    try:
        key = base64.urlsafe_b64decode(valor)
    except (binascii.Error, ValueError):
        key = b''
    if len(key) != 32:
        raise RuntimeError('%s debe ser de 32 bytes en base64 url-safe' % origen)
    return key


def _llave_del_mfa():
    """Los bytes de TOTP_ENCRYPTION_KEY, o None si no está o no se decodifica (de eso se queja cirdan/auth/totp.py)."""
    valor = config('TOTP_ENCRYPTION_KEY')
    try:
        return _decodificar(valor, 'TOTP_ENCRYPTION_KEY') if valor else None
    except RuntimeError:
        return None


def _secreto(url):
    """(bóveda, nombre) del secreto de una URL de Key Vault, sin la versión y en minúsculas, porque Key Vault no
    distingue mayúsculas en esos nombres. Dos versiones del mismo secreto son el mismo secreto."""
    try:
        partes = urllib.parse.urlsplit(url)
    except ValueError:
        return url, None
    return (partes.hostname or '').lower(), (partes.path.split('/')[2:3] or [''])[0].lower()


def _variables():
    """(url, None) o (None, llave directa ya decodificada), con una sola de las dos variables puesta, o RuntimeError.
    Vacía cuenta como sin poner. No usa la red."""
    url = config(VARIABLE_URL)
    directa = config(VARIABLE_LLAVE)
    if url and directa:
        raise RuntimeError('%s y %s están puestas: con Key Vault, quita %s del .env'
                           % (VARIABLE_URL, VARIABLE_LLAVE, VARIABLE_LLAVE))
    if not url and not directa:
        raise RuntimeError('Falta %s o %s: copia .env.example como .env y llena sus valores'
                           % (VARIABLE_LLAVE, VARIABLE_URL))
    if directa:
        llave = _decodificar(directa, VARIABLE_LLAVE)
        mfa = _llave_del_mfa()
        if mfa is not None and hmac.compare_digest(llave, mfa):
            raise RuntimeError('%s debe ser otra llave que TOTP_ENCRYPTION_KEY' % VARIABLE_LLAVE)
        return None, llave
    otra = config('TOTP_KEY_VAULT_SECRET_URL')
    if otra and _secreto(url) == _secreto(otra):
        raise RuntimeError('%s debe ser otro secreto que TOTP_KEY_VAULT_SECRET_URL, no otra versión del mismo'
                           % VARIABLE_URL)
    return url, None


def revisar_variables():
    """Sin red ni Key Vault: que venga una sola de las dos variables y que la llave directa sea de 32 bytes y otra que
    la del MFA. La usa el script de demo, que corre antes que la API, para que `docker compose up` falle con este
    mensaje en vez de dejar la API reiniciándose."""
    _variables()


def llave_en_key_vault():
    """True si la llave sale de Key Vault. Sin red: la usa el script de demo, que en la VM no llega a IMDS."""
    return _variables()[0] is not None


def _key():
    url, llave = _variables()
    if llave is not None:
        return llave
    global _llave_vault
    with _candado:
        if _llave_vault is None or _llave_vault[0] != url:
            secreto = keyvault.leer_secreto(url, variable=VARIABLE_URL)
            _llave_vault = (url, _decodificar(secreto, 'El secreto de Key Vault de ' + VARIABLE_URL))
        return _llave_vault[1]


def _dato_asociado(user_id):
    """El id del usuario en su forma canónica: '...-ABC' y '...-abc' cifran igual. ValueError si no es un UUID."""
    return str(uuid.UUID(str(user_id))).encode()


def _cifrar(phc, user_id, key):
    nonce = os.urandom(12)
    blob = nonce + AESGCM(key).encrypt(nonce, phc.encode(), _dato_asociado(user_id))
    return PREFIJO + base64.urlsafe_b64encode(blob).decode()


def _descifrar(guardada, user_id):
    """La cadena PHC de una huella 'lt1$', o None si no abre con esta llave y este usuario."""
    try:
        blob = base64.b64decode(guardada[len(PREFIJO):], altchars=b'-_', validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(blob) < 12 + 16:
        return None
    try:
        return AESGCM(_key()).decrypt(blob[:12], blob[12:], _dato_asociado(user_id)).decode()
    except (InvalidTag, ValueError):
        return None


def _relleno_phc():
    global _phc_relleno
    with _candado:
        if _phc_relleno is None:
            _phc_relleno = _hasher.hash(_RELLENO)
        return _phc_relleno


def _huella_relleno():
    global _relleno
    key = _key()
    phc = _relleno_phc()
    with _candado:
        if _relleno is None or _relleno[0] != key:
            _relleno = (key, _cifrar(phc, _ID_RELLENO, key))
        return _relleno[1]


def comprobar_llave(llave_mfa=None):
    """Al arrancar la API: sin llave válida no arranca, en vez de fallar en el primer inicio de sesión. Con
    `llave_mfa`, los bytes que devuelve totp.comprobar_llave(), tampoco arranca si las dos son la misma, aunque una
    venga del .env y la otra de Key Vault. También deja lista la huella de relleno, para que el primer correo
    inexistente no tarde un argon2id de más."""
    key = _key()
    if llave_mfa is not None and hmac.compare_digest(key, llave_mfa):
        variable = VARIABLE_URL if llave_en_key_vault() else VARIABLE_LLAVE
        raise RuntimeError('%s da la misma llave que la del MFA: las huellas van con otra llave' % variable)
    _huella_relleno()


def hash_password(password, user_id):
    """Huella 'lt1$' de `password` para el usuario `user_id`: argon2id y luego AES-256-GCM."""
    return _cifrar(_hasher.hash(password), user_id, _key())


def _verificar_phc(phc, password):
    try:
        return _hasher.verify(phc, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_password(password_hash, password, user_id):
    """True si `password` abre la huella guardada de `user_id`. Acepta la huella cifrada y la vieja sin cifrar.

    Una huella que no abre (otra llave, otro id, dañada o de otra forma) gasta igual un argon2id, el del relleno: así
    ese correo no responde más rápido que uno que no existe (punto 5 de RC-330)."""
    phc = None
    if isinstance(password_hash, str):
        if password_hash.startswith(PREFIJO):
            phc = _descifrar(password_hash, user_id)
        elif password_hash.startswith(VIEJA):
            phc = password_hash
    if phc is None:
        _verificar_phc(_relleno_phc(), password)
        return False
    return _verificar_phc(phc, password)


def burn_time(password):
    """Gasta el mismo tiempo que una verificación real (correo inexistente): descifrar y argon2id."""
    verify_password(_huella_relleno(), password, _ID_RELLENO)


def needs_rehash(password_hash, user_id):
    """True si hay que volver a guardar la huella: sin cifrar, que no abre o con otros parámetros de argon2id."""
    if not isinstance(password_hash, str) or not password_hash.startswith(PREFIJO):
        return True
    phc = _descifrar(password_hash, user_id)
    if phc is None:
        return True
    try:
        return _hasher.check_needs_rehash(phc)
    except InvalidHashError:
        return True

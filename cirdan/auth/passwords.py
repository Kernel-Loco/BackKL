"""Contraseñas con argon2id (OWASP ASVS V2.4). Nunca se guardan ni se registran en claro."""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 12   # misma política que el portal (src/lib/validation.ts)
MAX_LENGTH = 128

_hasher = PasswordHasher()  # argon2id, t=3, m=64 MiB, p=4
# Hash de relleno: con un correo que no existe se verifica contra él, para que la respuesta
# tarde lo mismo que con una contraseña equivocada y no se puedan adivinar correos.
_DUMMY = _hasher.hash('lowtide-relleno-que-nunca-coincide')


def hash_password(password):
    return _hasher.hash(password)


def verify_password(password_hash, password):
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def burn_time(password):
    """Gasta el mismo tiempo que una verificación real (correo inexistente)."""
    verify_password(_DUMMY, password)


def needs_rehash(password_hash):
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True

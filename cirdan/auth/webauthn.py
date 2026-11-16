"""Passkeys (WebAuthn) con py_webauthn (RC-331). La firma, el reto, el origen y el RP ID los revisa la librería; aquí va
lo que es de LowTide: de dónde salen el RP ID y los orígenes, que siempre se exija verificación del usuario y que el
JSON del navegador no pase de un tamaño.

- WEBAUTHN_RP_ID: el dominio al que quedan amarradas las passkeys. localhost en desarrollo y lowtidesec.com en la VM.
  Si el dominio cambia, las passkeys dejan de servir y se entra con contraseña y TOTP.
- Los orígenes aceptados son los de ALLOWED_ORIGINS (o la lista local por omisión) cuyo host es el RP ID o un subdominio
  suyo: en la VM, https://lowtidesec.com y https://www.lowtidesec.com. Con http solo localhost.

Las respuestas del navegador llegan como JSON (el de @simplewebauthn/browser) y se pasan tal cual a la librería.
"""
import json
import uuid
from functools import cache
from urllib.parse import urlsplit

from webauthn import (generate_authentication_options, generate_registration_options, verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json_dict
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, AuthenticatorTransport,
                                      PublicKeyCredentialDescriptor, ResidentKeyRequirement,
                                      UserVerificationRequirement)

from cirdan.config import ORIGENES_LOCALES, config

RP_NAME = 'LowTide'
# Lo que tarda el navegador en dejar de esperar a la persona. El reto en Valkey vive 5 min (sessions.PASSKEY_SECONDS).
TIMEOUT_MS = 2 * 60 * 1000
MAX_CREDENTIAL_JSON = 16 * 1024       # una respuesta real pesa 1 a 3 KB
MAX_CREDENTIAL_ID = 1023              # WebAuthn nivel 3 y el CHECK de la migración 017
TRANSPORTS = {t.value for t in AuthenticatorTransport}


class PasskeyError(Exception):
    """La respuesta del navegador no sirve: mal formada, de otro origen, sin verificación del usuario o mal firmada."""


@cache
def rp_id():
    return (config('WEBAUTHN_RP_ID') or 'localhost').strip().lower()


def _origin_ok(origin, rp):
    parts = urlsplit(origin)
    host = (parts.hostname or '').lower()
    if parts.path not in ('', '/') or parts.query or parts.fragment or parts.username or parts.password:
        return False
    if host != rp and not host.endswith('.' + rp):
        return False
    return parts.scheme == 'https' or (parts.scheme == 'http' and host == 'localhost')


@cache
def origins():
    """Orígenes de ALLOWED_ORIGINS que pueden usar passkeys de este RP ID, sin barra final."""
    allowed = (config('ALLOWED_ORIGINS') or ORIGENES_LOCALES).split(',')
    rp = rp_id()
    return sorted({o.strip().rstrip('/') for o in allowed if o.strip() and _origin_ok(o.strip(), rp)})


def configured():
    return bool(rp_id()) and bool(origins())


def user_handle(user_id):
    """El user handle de WebAuthn: los 16 bytes del users.id. No lleva el correo ni el nombre."""
    return uuid.UUID(str(user_id)).bytes


def _uv_required():
    return UserVerificationRequirement.REQUIRED


# ------------------------------------------------------------------ registrar

def registration_options(user_id, email, display_name, existing_ids):
    """Opciones para navigator.credentials.create() y el reto que hay que guardar. Passkey descubrible (para entrar sin
    escribir el correo) y con verificación del usuario. Las que ya tiene la cuenta van en excludeCredentials."""
    options = generate_registration_options(
        rp_id=rp_id(), rp_name=RP_NAME, user_name=email, user_id=user_handle(user_id),
        user_display_name=display_name or email, timeout=TIMEOUT_MS,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=_uv_required()),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=bytes(c)) for c in existing_ids])
    return options_to_json_dict(options), options.challenge


def _limited(credential):
    if not isinstance(credential, dict) or len(json.dumps(credential)) > MAX_CREDENTIAL_JSON:
        raise PasskeyError('respuesta mal formada')
    return credential


def verify_registration(credential, challenge):
    """Revisa la respuesta de navigator.credentials.create(). Devuelve lo que se guarda en webauthn_credentials."""
    credential = _limited(credential)
    try:
        result = verify_registration_response(
            credential=credential, expected_challenge=challenge, expected_rp_id=rp_id(),
            expected_origin=origins(), require_user_presence=True, require_user_verification=True)
    except Exception as exc:  # solo la librería corre aquí: cualquier error de la respuesta es un fallo
        raise PasskeyError(str(exc)) from exc
    if not result.user_verified:  # la librería ya lo exige; va dos veces porque sin esto no cuenta como MFA
        raise PasskeyError('sin verificación del usuario')
    if not 1 <= len(result.credential_id) <= MAX_CREDENTIAL_ID:
        raise PasskeyError('id de credencial fuera de tamaño')
    transports = (credential.get('response') or {}).get('transports') or []
    if not isinstance(transports, list):
        transports = []
    aaguid = None
    try:
        aaguid = uuid.UUID(result.aaguid) if result.aaguid else None
    except ValueError:
        pass
    return {'credential_id': result.credential_id, 'public_key': result.credential_public_key,
            'sign_count': result.sign_count, 'aaguid': aaguid, 'backed_up': bool(result.credential_backed_up),
            'transports': sorted({t for t in transports if isinstance(t, str) and t in TRANSPORTS})}


# ------------------------------------------------------------------ entrar

def authentication_options():
    """Opciones para navigator.credentials.get() sin allowCredentials: el navegador ofrece las passkeys que tenga para
    este RP ID (botón y autollenado). Devuelve también el reto que hay que guardar."""
    options = generate_authentication_options(rp_id=rp_id(), timeout=TIMEOUT_MS, user_verification=_uv_required())
    return options_to_json_dict(options), options.challenge


def credential_id_of(credential):
    """El id de la credencial de la respuesta (rawId), sin revisar nada más; None si no se puede leer."""
    try:
        raw = _limited(credential).get('rawId')
        if not isinstance(raw, str) or credential.get('id') != raw:
            return None
        value = base64url_to_bytes(raw)
    except (PasskeyError, ValueError, TypeError):
        return None
    # El decodificador de Python ignora lo que no es base64url: solo vale la forma canónica.
    if bytes_to_base64url(value) != raw:
        return None
    return value if 1 <= len(value) <= MAX_CREDENTIAL_ID else None


def user_handle_of(credential):
    """El userHandle de la respuesta; None si no viene o no se lee."""
    try:
        raw = (credential.get('response') or {}).get('userHandle')
        return base64url_to_bytes(raw) if isinstance(raw, str) and raw else None
    except (ValueError, TypeError, AttributeError):
        return None


def verify_authentication(credential, challenge, public_key, sign_count):
    """Revisa la respuesta de navigator.credentials.get() con la llave pública guardada. Devuelve el contador nuevo y
    si el proveedor respalda la passkey."""
    credential = _limited(credential)
    try:
        result = verify_authentication_response(
            credential=credential, expected_challenge=challenge, expected_rp_id=rp_id(),
            expected_origin=origins(), credential_public_key=bytes(public_key),
            credential_current_sign_count=int(sign_count), require_user_verification=True)
    except Exception as exc:  # solo la librería corre aquí: cualquier error de la respuesta es un fallo
        raise PasskeyError(str(exc)) from exc
    if not result.user_verified:
        raise PasskeyError('sin verificación del usuario')
    return result.new_sign_count, bool(result.credential_backed_up)

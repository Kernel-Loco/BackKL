"""Captcha del inicio de sesión (RC-154): ALTCHA autohospedado, una prueba de trabajo que el navegador resuelve
sin terceros, sin cookies y sin red fuera del portal.

1. GET /api/v1/auth/captcha da un reto nuevo firmado con HMAC-SHA256 que vence en CHALLENGE_SECONDS.
2. El widget altcha del portal (npm) busca el contador que hace que PBKDF2-SHA256 de una llave que empiece con
   KEY_PREFIX y manda el resultado en el campo `captcha` de /login.
3. verify() revisa firma, vencimiento y solución con la librería altcha de PyPI, sin red, y gasta el reto una sola
   vez en Valkey: el mismo resultado no sirve para un segundo intento.

La llave HMAC no va en el .env: es una al azar que se guarda en Valkey la primera vez y comparten todos los
procesos de la API. Si Valkey se reinicia nace otra, y los retos ya emitidos dejan de servir (el portal pide uno
nuevo). Quien pudiera leer Valkey solo se ahorraría la prueba de trabajo: las sesiones ahí van por su SHA-256.
"""
import logging
import secrets
import time

import altcha

from cirdan.auth import sessions

log = logging.getLogger(__name__)

ALGORITHM = 'PBKDF2/SHA-256'
# Unas 256 derivaciones de 5,000 vueltas en promedio: cerca de medio segundo en una laptop y un par en un teléfono.
COST = 5_000
KEY_PREFIX = '00'
CHALLENGE_SECONDS = 10 * 60
# Un resultado del widget mide unos 500 caracteres. Lo que pase de aquí ni se decodifica.
MAX_PAYLOAD = 4_096


def _key():
    return sessions.captcha_hmac_key(secrets.token_hex(32))


def new_challenge():
    """Reto nuevo, listo para mandarlo como JSON al widget."""
    challenge = altcha.create_challenge(ALGORITHM, COST, key_prefix=KEY_PREFIX,
                                        expires_at=int(time.time()) + CHALLENGE_SECONDS, hmac_secret=_key())
    return challenge.to_dict()


def verify(payload):
    """True solo si el resultado es de un reto de esta API, no venció, la solución es correcta y nadie lo había
    usado. Lo que no se pueda leer cuenta como inválido, nunca como error del servidor."""
    if not isinstance(payload, str) or not payload or len(payload) > MAX_PAYLOAD:
        return False
    key = _key()  # fuera del try: si Valkey no contesta es un 500, no un captcha inválido
    try:
        parsed = altcha.Payload.from_base64(payload)
        result = altcha.verify_solution(parsed, key)
        params = parsed.challenge.parameters
        if not result.verified or params.algorithm != ALGORITHM or not isinstance(params.expires_at, int):
            return False
        nonce = params.nonce
    except Exception:  # base64, JSON o tipos raros: la librería no los atrapa todos
        return False
    # Hasta que vence: después de eso el reto ya no pasa la revisión de arriba.
    return sessions.spend_captcha(nonce, max(1, params.expires_at - int(time.time()) + 1))

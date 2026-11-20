"""Reto CAPTCHA ALTCHA autocontenido: crea y verifica pruebas de trabajo."""
import datetime
import secrets

import altcha

from cirdan.auth import sessions


def nuevo_reto():
    key = sessions.captcha_key()
    reto = altcha.create_challenge_v1(
        hmac_key=key,
        expires=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10),
    )
    dato = reto.to_dict()
    sessions.register_captcha_challenge(dato['challenge'])
    return dato


def verificar(payload):
    if not payload:
        return False
    if isinstance(payload, str):
        import base64, json
        try:
            payload = json.loads(base64.b64decode(payload).decode())
        except Exception:
            return False
    challenge = payload.get('challenge') if isinstance(payload, dict) else None
    if not challenge:
        return False
    valido, _ = altcha.verify_solution_v1(payload, sessions.captcha_key(), check_expires=True)
    if not valido:
        return False
    return sessions.consume_captcha_challenge(challenge)

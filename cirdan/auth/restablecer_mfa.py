"""Restablece el MFA de una cuenta cuyo secreto TOTP no abre con ninguna llave (RC-295).

Es el caso que da 401 'Habla con el Admin.' en /mfa/verify: la llave del MFA se perdió o se quitó la anterior con
cuentas pendientes. Sin esto solo quedaba tocar la base a mano. Corre dentro del contenedor de la API, como
cirdan_app y con el RLS de la empresa, y quien administra la VM da los dos ids, que postgres saca del correo:

    docker exec cirdan-pg16 psql -U postgres -d cirdan -Atc \
      "SELECT organization_id, id FROM users WHERE email = '<correo>'"
    docker compose exec -T api python -m cirdan.auth.restablecer_mfa <empresa> <usuario>        # solo revisa
    docker compose exec -T api python -m cirdan.auth.restablecer_mfa <empresa> <usuario> --si   # restablece

Solo restablece si el secreto guardado no abre con la actual ni con la anterior: un secreto que abre no se toca y el
comando termina con error. Con --si deja totp_secret_enc, mfa_enabled_at y last_totp_step en NULL en un solo UPDATE,
con la fila bloqueada, y en la misma transacción escribe auth.mfa_reset (actor 'system', reason 'key') en la bitácora.
Las passkeys de la cuenta no se tocan. Después, la cuenta activa otra vez su app autenticadora como la primera vez: un
Admin en el mismo /login, un operador por fuera como en su alta (no se da de alta al entrar, routes.py) y las demás
en su perfil. La salida no lleva secretos ni correos.
"""
import sys
import uuid

from cirdan.auth import totp
from cirdan.db import audit, transaction

USO = 'Uso: python -m cirdan.auth.restablecer_mfa <id de empresa> <id de usuario> [--si]'


def _uuid(texto, que):
    try:
        return str(uuid.UUID(texto))
    except ValueError:
        raise SystemExit('El %s no es un uuid. %s' % (que, USO)) from None


def restablecer(org, user_id, confirmar=False, salida=None):
    """True si restableció, False si solo revisó (sin `confirmar`). SystemExit si no hay nada que restablecer."""
    salida = salida or print
    totp.comprobar_llave()
    with transaction(org) as conn:
        fila = conn.execute('SELECT totp_secret_enc FROM users WHERE id = %s FOR UPDATE', (user_id,)).fetchone()
        if fila is None:
            raise SystemExit('No hay un usuario con ese id en esa empresa')
        if not fila['totp_secret_enc']:
            raise SystemExit('La cuenta no tiene secreto TOTP guardado: no hay nada que restablecer')
        try:
            _, con_anterior = totp.descifrar(fila['totp_secret_enc'], user_id)
        except totp.LlaveNoAbre:
            pass
        else:
            raise SystemExit('El secreto abre con la %s: la cuenta entra con su código y no se restablece'
                             % ('anterior' if con_anterior else 'actual'))
        if not confirmar:
            salida('El secreto no abre con ninguna llave. Con --si se restablece el MFA de la cuenta')
            return False
        conn.execute('UPDATE users SET totp_secret_enc = NULL, mfa_enabled_at = NULL, last_totp_step = NULL, '
                     'updated_at = now() WHERE id = %s', (user_id,))
        audit(conn, org, 'auth.mfa_reset', None, None, 'user', user_id, {'reason': 'key'})
    salida('MFA restablecido: la cuenta vuelve a activar su app autenticadora al entrar')
    return True


def main(argv, salida=None):
    args = argv[1:]
    confirmar = '--si' in args
    args = [a for a in args if a != '--si']
    if len(args) != 2:
        raise SystemExit(USO)
    org, user_id = _uuid(args[0], 'id de empresa'), _uuid(args[1], 'id de usuario')
    try:
        return restablecer(org, user_id, confirmar, salida)
    except RuntimeError as e:
        raise SystemExit(str(e)) from None


if __name__ == '__main__':
    main(sys.argv)

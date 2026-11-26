"""Cuenta los secretos TOTP que siguen cifrados con la llave anterior (RC-295), sin cambiar nada.

Corre dentro del contenedor de la API, que tiene las dos llaves y, en la VM, llega a Key Vault. La API entra a la base
como cirdan_app, con RLS, y no puede listar las empresas: las da postgres por la entrada, una por línea
(docs/despliegue.md, 'Rotar la llave del MFA'):

    set -o pipefail; docker exec cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 -Atc \
      "SELECT DISTINCT organization_id FROM users WHERE totp_secret_enc IS NOT NULL" \
      | docker compose exec -T api python -m cirdan.auth.contar_totp

Por empresa imprime cuántos abren con la actual, cuántos solo con la anterior y cuántos con ninguna, y al final el
total. Solo cuenta las cuentas que pueden entrar (activas y de una empresa en trial o active): las demás nunca llegan a
/mfa/verify, así que su secreto no se vuelve a cifrar, y van aparte como 'sin acceso'. Una entrada sin ninguna empresa
termina con error: es un psql que falló, no un 0. Solo lee: no bloquea filas, no vuelve a cifrar ni escribe en
audit_log. Ni la salida lleva secretos, correos ni ids de usuario.

Un secreto con la anterior se vuelve a cifrar con la actual en el siguiente código bueno de esa cuenta
(cirdan/auth/routes.py). La anterior se quita del .env solo con 0 en 'con la anterior' y con 'con ninguna' igual que en
el conteo de antes de rotar: si subió, la anterior no es la llave de antes. Una cuenta cuyo secreto no abre con ninguna
recibe 'Habla con el Admin.' al entrar, y quien administra la VM le restablece el MFA con
`python -m cirdan.auth.restablecer_mfa`, que solo lo hace si de verdad ninguna llave lo abre.
"""
import sys
import uuid

from cirdan.auth import totp
from cirdan.db import transaction

CLAVES = ('actual', 'anterior', 'ninguna', 'sin_acceso')
SIN_EMPRESAS = ('La entrada no trae ninguna empresa. Si el psql falló, su error está arriba. Si de verdad ninguna cuenta '
                'tiene MFA, no hay nada que contar.')


def _empresas(lineas):
    """Los ids de empresa de la entrada, sin repetir y en orden, o SystemExit con la primera línea que no es un uuid."""
    vistos = []
    for numero, linea in enumerate(lineas, 1):
        texto = linea.strip()
        if not texto:
            continue
        try:
            org = str(uuid.UUID(texto))
        except ValueError:
            raise SystemExit('La línea %d de la entrada no es el id de una empresa' % numero) from None
        if org not in vistos:
            vistos.append(org)
    return vistos


def _una_empresa(org):
    conteo = dict.fromkeys(CLAVES, 0)
    with transaction(org) as conn:
        # Las mismas condiciones que /login y /link/verify (routes.py): sin ellas la cuenta no llega a /mfa/verify.
        filas = conn.execute(
            "SELECT u.id, u.totp_secret_enc, u.is_active AND o.status IN ('trial', 'active') AS puede_entrar "
            '  FROM users u JOIN organizations o ON o.id = u.organization_id '
            ' WHERE u.totp_secret_enc IS NOT NULL').fetchall()
    for fila in filas:
        if not fila['puede_entrar']:
            conteo['sin_acceso'] += 1
            continue
        try:
            _, con_anterior = totp.descifrar(fila['totp_secret_enc'], fila['id'])
        except totp.LlaveNoAbre:
            conteo['ninguna'] += 1
            continue
        conteo['anterior' if con_anterior else 'actual'] += 1
    return conteo


def _texto(conteo):
    return ('%d con la actual, %d con la anterior, %d con ninguna, %d sin acceso'
            % tuple(conteo[k] for k in CLAVES))


def contar(lineas, salida=None):
    """{'actual', 'anterior', 'ninguna', 'sin_acceso'} de todas las empresas de `lineas`. Sin `salida`, imprime."""
    salida = salida or print
    empresas = _empresas(lineas)
    if not empresas:
        raise SystemExit(SIN_EMPRESAS)
    totp.comprobar_llave()
    con_anterior = totp._llave_anterior() is not None
    if not con_anterior:
        salida('Sin llave anterior (%s o %s): todos los secretos que abren son de la actual'
               % (totp.VARIABLE_URL_ANTERIOR, totp.VARIABLE_LLAVE_ANTERIOR))
    total = dict.fromkeys(CLAVES, 0)
    for org in empresas:
        conteo = _una_empresa(org)
        salida('empresa %s: %s' % (org, _texto(conteo)))
        for k in total:
            total[k] += conteo[k]
    salida('Total: %s' % _texto(total))
    if total['sin_acceso']:
        salida("'sin acceso' son cuentas inactivas o de una empresa fuera de trial y active: no entran, así que su "
               'secreto no se vuelve a cifrar y no cuentan para quitar la anterior')
    if con_anterior and total['ninguna']:
        salida("Si 'con ninguna' es mayor que en el conteo de antes de rotar, la anterior no es la llave de antes: "
               'corrige el paso 2 y no la quites')
    return total


def main(argv, entrada=None):
    if argv[1:]:
        raise SystemExit('Uso: (ids de empresa, uno por línea) | python -m cirdan.auth.contar_totp')
    try:
        contar((entrada or sys.stdin).read().splitlines())
    except RuntimeError as e:
        raise SystemExit(str(e)) from None


if __name__ == '__main__':
    main(sys.argv)

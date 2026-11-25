"""Cuenta los secretos TOTP que siguen cifrados con la llave anterior (RC-295), sin cambiar nada.

Corre dentro del contenedor de la API, que tiene las dos llaves y, en la VM, llega a Key Vault. La API entra a la base
como cirdan_app, con RLS, y no puede listar las empresas: las da postgres por la entrada, una por línea
(docs/despliegue.md, 'Rotar la llave del MFA'):

    docker exec cirdan-pg16 psql -U postgres -d cirdan -Atc \
      "SELECT DISTINCT organization_id FROM users WHERE totp_secret_enc IS NOT NULL" \
      | docker compose exec -T api python -m cirdan.auth.contar_totp

Por empresa imprime cuántos abren con la actual, cuántos solo con la anterior y cuántos con ninguna, y al final el
total. Solo lee: no bloquea filas, no vuelve a cifrar ni escribe en audit_log. Ni la salida lleva secretos, correos
ni ids de usuario. Un secreto con la anterior se vuelve a cifrar con la actual en el siguiente código bueno de esa
cuenta (cirdan/auth/routes.py). La anterior se quita del .env solo con 0 en 'con la anterior'. Los que no abren con
ninguna ya no abrían antes: esa cuenta recibe 'Habla con el Admin.' al entrar y su MFA se restablece.
"""
import sys
import uuid

from cirdan.auth import totp
from cirdan.db import transaction


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
    conteo = {'actual': 0, 'anterior': 0, 'ninguna': 0}
    with transaction(org) as conn:
        filas = conn.execute('SELECT id, totp_secret_enc FROM users WHERE totp_secret_enc IS NOT NULL').fetchall()
    for fila in filas:
        try:
            _, con_anterior = totp.descifrar(fila['totp_secret_enc'], fila['id'])
        except totp.LlaveNoAbre:
            conteo['ninguna'] += 1
            continue
        conteo['anterior' if con_anterior else 'actual'] += 1
    return conteo


def contar(lineas, salida=None):
    """{'actual', 'anterior', 'ninguna'} de todas las empresas de `lineas`. Sin `salida`, imprime."""
    salida = salida or print
    totp.comprobar_llave()
    if totp._llave_anterior() is None:
        salida('Sin llave anterior (%s o %s): todos los secretos que abren son de la actual'
               % (totp.VARIABLE_URL_ANTERIOR, totp.VARIABLE_LLAVE_ANTERIOR))
    total = {'actual': 0, 'anterior': 0, 'ninguna': 0}
    for org in _empresas(lineas):
        conteo = _una_empresa(org)
        salida('empresa %s: %d con la actual, %d con la anterior, %d con ninguna'
               % (org, conteo['actual'], conteo['anterior'], conteo['ninguna']))
        for k in total:
            total[k] += conteo[k]
    salida('Total: %d con la actual, %d con la anterior, %d con ninguna'
           % (total['actual'], total['anterior'], total['ninguna']))
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

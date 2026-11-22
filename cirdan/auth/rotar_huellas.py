"""Vuelve a cifrar con la llave actual las huellas de contraseña de la versión anterior (RC-333), sin pedir
contraseñas: descifra la cadena PHC con la llave anterior y la cifra con la actual, con el mismo id como dato asociado.

Corre dentro del contenedor de la API, que tiene las llaves y, en la VM, llega a Key Vault (docs/despliegue.md):

    docker compose exec api python -m cirdan.auth.rotar_huellas --prueba   # solo cuenta, no cambia nada
    docker compose exec api python -m cirdan.auth.rotar_huellas

Pide `PASSWORD_HASH_KEY_VERSION` de 2 o más y la llave anterior puesta (cirdan/auth/passwords.py). Recorre las empresas
que tienen huellas de la versión anterior (password_hash_version_orgs(), migración 026) y cada una con RLS, como
cirdan_app. Cada cuenta va en su propia transacción con la fila bloqueada (FOR NO KEY UPDATE, el mismo candado del
login y del cambio de contraseña, que no choca con el FOR KEY SHARE de la llave de audit_log a users), así que un login
o un cambio de contraseña a la vez espera a que termine o se hace antes, y el UPDATE nunca pisa una huella nueva. Con
'--prueba' no bloquea nada. Por empresa con al menos una huella cambiada deja un evento `auth.password_hash_rotated`
en audit_log con los conteos. Si la corrida se corta a media empresa (Ctrl+C o un error), antes de salir deja el
evento de lo que ya cambió, con `interrupted`. Ni la salida ni la bitácora llevan huellas, correos ni ids de usuario.
Una segunda corrida no cambia nada ni escribe eventos: las que abrieron ya son de la versión actual y las que no
abrieron siguen sin abrir.
"""
import sys

from cirdan.auth import passwords, totp
from cirdan.db import audit, transaction

ACCION = 'auth.password_hash_rotated'


def _empresas(version):
    with transaction() as conn:
        return [str(r['organization_id']) for r in conn.execute(
            'SELECT organization_id FROM public.password_hash_version_orgs(%s) ORDER BY organization_id', (version,))]


def _patron(version):
    # Sin comodines de LIKE en el prefijo: 'lt1$' solo lleva letras, un número y '$'.
    return passwords.prefijo(version) + '%'


def _quedan(org, version):
    with transaction(org) as conn:
        return conn.execute('SELECT count(*) AS n FROM users WHERE password_hash LIKE %s',
                            (_patron(version),)).fetchone()['n']


def _una_cuenta(org, user_id, version, prueba):
    """'cambiada', 'no abre' o None si ya no es de la versión anterior (la cambió otra petición mientras tanto)."""
    with transaction(org) as conn:
        # Con '--prueba' solo se lee: no hace falta bloquear la fila.
        fila = conn.execute('SELECT password_hash FROM users WHERE id = %s AND password_hash LIKE %s'
                            + ('' if prueba else ' FOR NO KEY UPDATE'), (user_id, _patron(version))).fetchone()
        if not fila:
            return None
        nueva = passwords.recifrar(fila['password_hash'], user_id)
        if nueva is None:
            return 'no abre'
        if not prueba:
            conn.execute('UPDATE users SET password_hash = %s WHERE id = %s', (nueva, user_id))
        return 'cambiada'


def _evento(org, anterior, actual, conteo, quedan, cortada=False):
    detalles = {'from_version': anterior, 'to_version': actual, 'changed': conteo['cambiada'],
                'unopened': conteo['no abre'], 'remaining': quedan}
    if cortada:
        detalles['interrupted'] = True
    with transaction(org) as conn:
        audit(conn, org, ACCION, details=detalles)


def rotar(prueba=False, salida=print):
    """Devuelve (cambiadas, no abrieron, quedan) de todas las empresas. Con `prueba` solo cuenta: no cambia ninguna
    huella ni escribe en audit_log, y `quedan` es lo que hay hoy."""
    passwords.comprobar_llave(totp.comprobar_llave())
    actual = passwords.version_actual()
    if actual < 2 or passwords._llave_anterior() is None:
        raise SystemExit('Falta la llave anterior: pon %s o %s con la llave de la versión %d y %s en %d'
                         % (passwords.VARIABLE_URL_ANTERIOR, passwords.VARIABLE_LLAVE_ANTERIOR, max(actual - 1, 1),
                            passwords.VARIABLE_VERSION, max(actual, 2)))
    anterior = actual - 1
    total = [0, 0, 0]
    for org in _empresas(anterior):
        with transaction(org) as conn:
            ids = [str(r['id']) for r in conn.execute(
                'SELECT id FROM users WHERE password_hash LIKE %s ORDER BY id', (_patron(anterior),))]
        conteo = {'cambiada': 0, 'no abre': 0}
        con_evento = False
        try:
            for user_id in ids:
                resultado = _una_cuenta(org, user_id, anterior, prueba)
                if resultado:
                    conteo[resultado] += 1
            # Dentro del try: si la base falla aquí, después de la última cuenta, también queda el aviso.
            quedan = _quedan(org, anterior)
            # Sin cambios no hay evento: la bitácora no se puede borrar y una segunda corrida no debe sumarle nada.
            if not prueba and conteo['cambiada']:
                _evento(org, anterior, actual, conteo, quedan)
                con_evento = True
        except BaseException:
            # Cada cuenta ya cambiada quedó confirmada en su transacción: su evento se escribe antes de salir. Si la
            # base es la que falló, o llega otro Ctrl+C mientras tanto, tampoco se puede escribir, y la salida lo dice.
            # El raise de abajo sigue siendo el de la falla original.
            if not prueba and conteo['cambiada'] and not con_evento:
                try:
                    _evento(org, anterior, actual, conteo, _quedan(org, anterior), cortada=True)
                except BaseException:
                    salida('empresa %s: %d cambiadas sin evento en audit_log, la corrida se cortó'
                           % (org, conteo['cambiada']))
            raise
        salida('empresa %s: %d %s, %d no abrieron, quedan %d de la versión %d'
               % (org, conteo['cambiada'], 'se cambiarían' if prueba else 'cambiadas', conteo['no abre'], quedan,
                  anterior))
        total[0] += conteo['cambiada']
        total[1] += conteo['no abre']
        total[2] += quedan
    salida('%s: %d %s, %d no abrieron, quedan %d de la versión %d'
           % ('Prueba sin cambios' if prueba else 'Listo', total[0], 'se cambiarían' if prueba else 'cambiadas',
              total[1], total[2], anterior))
    return tuple(total)


def main(argv):
    if argv[1:] not in ([], ['--prueba']):
        raise SystemExit('Uso: python -m cirdan.auth.rotar_huellas [--prueba]')
    try:
        rotar(prueba=argv[1:] == ['--prueba'])
    except RuntimeError as e:
        raise SystemExit(str(e)) from None


if __name__ == '__main__':
    main(sys.argv)

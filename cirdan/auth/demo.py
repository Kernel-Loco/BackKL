"""Cuentas de demostración: contraseña y MFA de los usuarios de la semilla (db/semillas/001).

La semilla trae hashes de relleno que no sirven para entrar. Este script, que corre solo en
`docker compose up` cuando `DEMO_ACCOUNTS=true`, les pone la contraseña de demo y un secreto
TOTP cifrado con la llave del `.env`. Los secretos son fijos y públicos a propósito: se
agregan una vez a la app autenticadora. NUNCA activar DEMO_ACCOUNTS en producción.

Segundo candado, por si el `.env` de un despliegue se armó copiando uno de desarrollo: si
`ALLOWED_ORIGINS` trae algún origen que no sea localhost ni 127.0.0.1, la API está publicada y
el script no toca las cuentas aunque `DEMO_ACCOUNTS` sea true (#169, RC-287). Un origen local con barra final,
ruta o pegado a otro sin coma tampoco cuenta como local.

    python -m cirdan.auth.demo                 # pone las credenciales (idempotente)
    python -m cirdan.auth.demo codigo CORREO   # código TOTP vigente de una cuenta de demo
"""
import sys
from urllib.parse import urlsplit

import pyotp

from cirdan.auth import passwords, totp
from cirdan.config import ORIGENES_LOCALES, config
from cirdan.db import transaction

LOCALES = ('localhost', '127.0.0.1')

PASSWORD = 'Lowtide-Demo-2026'
ACME = '20000000-0000-4000-8000-000000000001'
BETA = '20000000-0000-4000-8000-000000000002'
OLMARDO = '20000000-0000-4000-8000-000000000003'  # dominio de prueba del equipo (db/semillas/002)

# correo: (empresa, id del usuario, secreto TOTP en base32)
CUENTAS = {
    'alex.morgan@acme-demo.mx': (ACME, '30000000-0000-4000-8000-000000000001', 'UGXK2GMMQ65BHJLIVR6NNDOAKMMRVLW5'),
    'maya.reed@acme-demo.mx': (ACME, '30000000-0000-4000-8000-000000000002', '3BU6UYVDTBEQMASX2IGWUOJGGJBXMLZW'),
    'jordan.tate@acme-demo.mx': (ACME, '30000000-0000-4000-8000-000000000003', 'OZTNVMHSFGXI7VAG2ACGA7TSNCUE3S6H'),
    'dana.cruz@beta-corp.mx': (BETA, '30000000-0000-4000-8000-000000000004', 'CMPPTNCOFPU3YUPJB4KJGFDMN5QZPXOV'),
    'admin@olmardo.com': (OLMARDO, '30000000-0000-4000-8000-000000000005', 'SNSA4TTR4FCTTDMKEYMPWGD6ZAKG3G5B'),
}


def poner_credenciales():
    hash_ = passwords.hash_password(PASSWORD)
    for email, (org, user_id, secreto) in CUENTAS.items():
        with transaction(org) as conn:
            conn.execute(
                'UPDATE users SET password_hash = %s, totp_secret_enc = %s, last_totp_step = NULL, '
                'mfa_enabled_at = coalesce(mfa_enabled_at, now()) WHERE id = %s',
                (hash_, totp.encrypt_secret(secreto, user_id), user_id))
        print('cuenta de demo lista:', email)


def codigo(email):
    return pyotp.TOTP(CUENTAS[email.lower()][2]).now()


def _es_local(origen):
    """Si `origen` es solo `http://` o `https://` más localhost o 127.0.0.1, con o sin puerto, sin distinguir
    mayúsculas.

    Lo que traiga otra cosa (ruta, usuario, espacios, otro origen pegado con espacio o con `;`) o no se pueda leer
    como origen no es local: una lista mal separada no debe pasar por local."""
    try:
        partes = urlsplit(origen)
        if partes.scheme not in ('http', 'https') or partes.hostname not in LOCALES:
            return False
        puerto = partes.port  # ValueError si el puerto no es un número
    except ValueError:
        return False
    esperado = '%s://%s' % (partes.scheme, partes.hostname)
    if puerto is not None:
        esperado += ':%d' % puerto
    return origen.lower() == esperado


def origenes_publicados():
    """Los valores de `ALLOWED_ORIGINS` que `_es_local` no acepta como origen local, en orden alfabético. Sin la
    variable vale la lista por omisión de la API (ORIGENES_LOCALES), que es toda local. Vacía, aquí se toma como
    sin poner. La API (cirdan/api/main.py) la toma como ningún origen."""
    declarados = [o.strip() for o in (config('ALLOWED_ORIGINS') or '').split(',') if o.strip()]
    return sorted(o for o in declarados or ORIGENES_LOCALES.split(',') if not _es_local(o))


def main(argv):
    if len(argv) == 3 and argv[1] == 'codigo':
        print(codigo(argv[2]))
        return
    if config('DEMO_ACCOUNTS', 'false').lower() != 'true':
        print('DEMO_ACCOUNTS no es true: no se tocan las cuentas.')
        return
    publicados = origenes_publicados()
    if publicados:
        print('ALLOWED_ORIGINS trae un origen que no es localhost ni 127.0.0.1 (%s): no se tocan las cuentas de demo, '
              'aunque DEMO_ACCOUNTS sea true. Un origen local se escribe sin barra final ni ruta, como '
              'http://localhost:3000.' % ', '.join(publicados))
        return
    poner_credenciales()


if __name__ == '__main__':
    main(sys.argv)

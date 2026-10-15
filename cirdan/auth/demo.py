"""Cuentas de demostración: contraseña y MFA de los usuarios de la semilla (db/semillas/001).

La semilla trae hashes de relleno que no sirven para entrar. Este script, que corre solo en
`docker compose up` cuando `DEMO_ACCOUNTS=true`, les pone la contraseña de demo y un secreto
TOTP cifrado con la llave del `.env`. Los secretos son fijos y públicos a propósito: se
agregan una vez a la app autenticadora. NUNCA activar DEMO_ACCOUNTS en producción.

    python -m cirdan.auth.demo                 # pone las credenciales (idempotente)
    python -m cirdan.auth.demo codigo CORREO   # código TOTP vigente de una cuenta de demo
"""
import sys

import pyotp

from cirdan.auth import passwords, totp
from cirdan.config import config
from cirdan.db import transaction

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


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'codigo':
        print(codigo(sys.argv[2]))
    elif config('DEMO_ACCOUNTS', 'false').lower() != 'true':
        print('DEMO_ACCOUNTS no es true: no se tocan las cuentas.')
    else:
        poner_credenciales()

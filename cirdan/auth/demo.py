"""Cuentas de demostración: contraseña y MFA de los usuarios de la semilla (db/semillas/001).

La semilla trae hashes de relleno que no sirven para entrar. Este script, que corre solo en
`docker compose up` cuando `DEMO_ACCOUNTS=true`, les pone la contraseña de demo y un secreto
TOTP cifrado con la llave del `.env`. Los secretos son fijos y públicos a propósito: se
agregan una vez a la app autenticadora. NUNCA activar DEMO_ACCOUNTS en producción.

Segundo candado, por si el `.env` de un despliegue se armó copiando uno de desarrollo: si
`ALLOWED_ORIGINS` trae algún origen que no sea localhost ni 127.0.0.1, la API está publicada y
el script no les pone credenciales aunque `DEMO_ACCOUNTS` sea true (#169, RC-287). Un origen local con barra final,
ruta o pegado a otro sin coma tampoco cuenta como local.

En esos dos casos, sin `DEMO_ACCOUNTS=true` o con un origen publicado, el script además apaga las cuentas: les vuelve
a poner el hash de relleno de la semilla, les quita el secreto TOTP y les borra las passkeys (RC-331). Así un volumen de la base que ya traía las
credenciales públicas, como el de una PC de desarrollo que se usa para el plan B del despliegue, deja de servir para
entrar (#49, RC-91).

    python -m cirdan.auth.demo                 # pone o apaga las credenciales (idempotente)
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


# El mismo marcador de db/semillas/001_datos_demo.sql: no es un hash que argon2 pueda verificar, así que ninguna
# contraseña entra con él (passwords.verify_password da False). Va sin cifrar a propósito: con la forma de una huella
# vieja tampoco abre nada (RC-330).
HASH_DE_RELLENO = '$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0$ZGVtby1vbmx5'


def apagar_credenciales():
    """Les quita a las cuentas de demo la contraseña y el MFA públicos, y las passkeys que alguien les haya registrado con
    esas credenciales (RC-331). Idempotente.

    El UPDATE va por el id, así que una cuenta inactiva o de una empresa que no está activa también se apaga. Si no
    cambia ninguna fila (no hay fila con ese id en esa empresa), se pregunta a login_lookup() (migración 004) si ese
    correo todavía puede iniciar sesión:
    - si no puede, no hay nada que apagar y solo se avisa;
    - si puede, pero su hash no acepta la contraseña pública, es otra fila que este script nunca tocó (con otro id) y
      no se toca: solo se avisa (N2 de la ronda 3 de RC-91);
    - si entra con la contraseña pública, el script apaga las demás y termina con error: esa cuenta sigue con las
      credenciales públicas y la API, que espera a demo-accounts, no arranca (R3 de la revisión de RC-91);
    - si su huella va cifrada y la llave de las huellas está en Key Vault, este contenedor no la puede leer (en la VM
      no llega a IMDS, docs/despliegue.md). Tampoco se da por apagada: termina con error en seco, sin esperar a IMDS
      (RC-330).
    Las passkeys se borran por el mismo id del UPDATE. Las de una fila con otro id no se tocan: esa fila no tiene la
    contraseña de demo (si la tuviera, el script ya termina con error), así que sus passkeys no salieron de las
    credenciales públicas."""
    sin_apagar, sin_revisar = [], []
    en_key_vault = passwords.llave_en_key_vault()
    for email, (org, user_id, _) in CUENTAS.items():
        with transaction(org) as conn:
            cambiadas = conn.execute(
                'UPDATE users SET password_hash = %s, totp_secret_enc = NULL, last_totp_step = NULL, '
                'mfa_enabled_at = NULL WHERE id = %s',
                (HASH_DE_RELLENO, user_id)).rowcount
            # Una passkey registrada con la contraseña y el TOTP públicos seguiría entrando como MFA (RC-331).
            # Con un volumen anterior a la 018 la tabla no existe: no hay passkeys que borrar y la API debe arrancar (R2).
            passkeys = 0
            if conn.execute("SELECT to_regclass('public.webauthn_credentials') IS NOT NULL AS hay").fetchone()['hay']:
                passkeys = conn.execute('DELETE FROM webauthn_credentials WHERE user_id = %s', (user_id,)).rowcount
            fila = None if cambiadas else conn.execute(
                'SELECT user_id::text, password_hash FROM login_lookup(%s)', (email,)).fetchone()
        if passkeys:
            print('passkeys de la cuenta de demo borradas:', email, passkeys)
        if cambiadas:
            print('cuenta de demo apagada:', email)
        elif fila is None:
            print('cuenta de demo que no puede iniciar sesión, nada que apagar:', email)
        elif en_key_vault and str(fila['password_hash']).startswith(passwords.PREFIJO):
            sin_revisar.append(email)
        # Con una huella cifrada esto usa la llave directa del .env (RC-330). Si no sirve, el script termina con error
        # y la API no arranca: no se da por apagada una cuenta que no se pudo revisar.
        elif passwords.verify_password(fila['password_hash'], PASSWORD, fila['user_id']):
            sin_apagar.append(email)
        else:
            print('cuenta de demo con otro id y sin la contraseña de demo, no se toca:', email)
    if sin_apagar:
        raise SystemExit('ERROR: estas cuentas de demo entran con la contraseña pública, pero el UPDATE no cambió su '
                         'fila (¿otro id o empresa que los de CUENTAS?). No se apagaron: %s' % ', '.join(sin_apagar))
    if sin_revisar:
        raise SystemExit('ERROR: estas cuentas de demo pueden iniciar sesión con otro id que los de CUENTAS y su '
                         'huella va cifrada con la llave de Key Vault, que este script no lee. No se revisó si entran '
                         'con la contraseña pública: %s' % ', '.join(sin_revisar))


def poner_credenciales():
    for email, (org, user_id, secreto) in CUENTAS.items():
        # Una huella por cuenta: va cifrada con el id del usuario como dato asociado (RC-330).
        with transaction(org) as conn:
            conn.execute(
                'UPDATE users SET password_hash = %s, totp_secret_enc = %s, last_totp_step = NULL, '
                'mfa_enabled_at = coalesce(mfa_enabled_at, now()) WHERE id = %s',
                (passwords.hash_password(PASSWORD, user_id), totp.encrypt_secret(secreto, user_id), user_id))
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
    # Sin la llave del MFA la API no arranca. En desarrollo nadie espera a la API, así que sin esto `docker compose
    # up -d` terminaría bien y la API se quedaría reiniciándose. Como la API espera a este script, aquí sí se detiene
    # el `up` (#49, RC-91). Lo mismo con la llave de las huellas de contraseña (RC-330). Revisar las variables y
    # apagar las cuentas nunca leen Key Vault: apagar solo usa la llave de las huellas cuando va directa en el .env
    # (apagar_credenciales). poner_credenciales (DEMO_ACCOUNTS=true) sí lee de Key Vault las llaves que estén ahí, la de
    # las huellas, la del MFA o las dos. En la VM no corre, porque el archivo del despliegue fija DEMO_ACCOUNTS=false.
    try:
        totp.revisar_variables()
        passwords.revisar_variables()
    except RuntimeError as e:
        sys.exit(str(e))
    if len(argv) == 3 and argv[1] == 'codigo':
        print(codigo(argv[2]))
        return
    if config('DEMO_ACCOUNTS', 'false').lower() != 'true':
        print('DEMO_ACCOUNTS no es true: se apagan las cuentas de demo.')
        apagar_credenciales()
        return
    publicados = origenes_publicados()
    if publicados:
        print('ALLOWED_ORIGINS trae un origen que no es localhost ni 127.0.0.1 (%s): se apagan las cuentas de demo, '
              'aunque DEMO_ACCOUNTS sea true. Un origen local se escribe sin barra final ni ruta, como '
              'http://localhost:3000.' % ', '.join(publicados))
        apagar_credenciales()
        return
    poner_credenciales()


if __name__ == '__main__':
    main(sys.argv)

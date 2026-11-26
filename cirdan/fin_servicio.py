"""Fin del servicio de una empresa y cancelación de cuentas del portal (#140, RC-258). Comandos del operador.

Corren dentro del contenedor de la API, con un motivo que queda en la bitácora de la empresa:

    docker compose exec api python -m cirdan.fin_servicio terminar <empresa> --motivo "..."
    docker compose exec api python -m cirdan.fin_servicio cancelar-usuario <usuario> --organizacion <empresa> --motivo "..."

**terminar** (sección 5.6 de la política: al vencer o revocarse la última carta, al cerrar el curso o cuando la empresa
lo pide por escrito; el plazo es de [30] días desde ese hecho): con el rol `cirdan_retention` y RLS de la empresa,
- marca la empresa `cancelled` con `service_ended_at`, pausa sus dominios, desactiva sus cuentas y revoca sus llaves;
- borra sus entregas, alertas, aportes y scores (la migración 037 se lo permite a una empresa con `service_ended_at`),
  hallazgos con su brecha, activos, reportes, corridas y escaneos;
- deja `service.ended` en su bitácora con el motivo y cuántas filas borró por tabla, sin datos de las filas;
- cierra las sesiones abiertas de sus cuentas y manda la confirmación a quien firmó sus cartas.
Las cartas, las verificaciones del TXT y la bitácora no se borran: su [plazo] queda como riesgo aceptado (sección 9).

**cancelar-usuario** (derecho de cancelación de una persona usuaria del portal): con `cirdan_app` y RLS, borra la
huella de la contraseña (pone el hash de relleno que no abre nada), la semilla TOTP y sus passkeys, desactiva la cuenta,
revoca sus llaves, marca `cancelled_at`, cierra sus sesiones y deja `user.cancelled`. El nombre y el correo se
anonimizan al vencer el plazo, con el job de retención (cirdan/retencion.py). La cadena de la bitácora no se rompe: solo
guarda el id del actor.
"""
import argparse
import html
import logging
import sys
import uuid

from psycopg.types.json import Jsonb

from cirdan import retencion

log = logging.getLogger('cirdan.fin_servicio')

LOTE = 500
# Todo lo de la empresa, en el orden de la retención: primero lo que apunta y al final lo apuntado. Los activos se
# borran de las hojas hacia la raíz, por eso su paso pide que no tengan hijos y se repite hasta vaciar.
BORRAR = (
    ('deliveries', 'true'),
    ('alerts', 'true'),
    ('score_contributions', 'true'),
    ('domain_scores', 'NOT EXISTS (SELECT 1 FROM alerts a WHERE a.score_id = t.id)'),
    ('breach_exposures', 'true'),
    ('findings', 'true'),
    ('assets', 'NOT EXISTS (SELECT 1 FROM assets h WHERE h.parent_asset_id = t.id)'),
    ('reports', 'true'),
    ('scan_source_runs', 'true'),
    ('scans', 'NOT EXISTS (SELECT 1 FROM domain_scores ds WHERE ds.scan_id = t.id)'),
)
ASUNTO = 'LowTide: borramos los análisis de tu empresa'


class Error(Exception):
    """El comando no se puede hacer. El mensaje es para la terminal del operador."""


def _motivo(motivo):
    limpio = ' '.join((motivo or '').split())
    if not 3 <= len(limpio) <= 300:
        raise Error('El motivo debe tener entre 3 y 300 caracteres.')
    return limpio


def _uuid(valor, que):
    try:
        return str(uuid.UUID(valor))
    except (ValueError, TypeError):
        raise Error('%s no es un id válido.' % que) from None


def _sentencia(tabla, condicion):
    llave = 'finding_id' if tabla == 'breach_exposures' else 'id'
    return ('DELETE FROM {t} WHERE {k} IN (SELECT t.{k} FROM {t} t WHERE t.organization_id = %(org)s AND {c} '
            'LIMIT %(lote)s)').format(t=tabla, k=llave, c=condicion)


def terminar(conn, org, motivo):
    """Borra lo de la empresa en una transacción. Devuelve {'filas': {tabla: n}, 'usuarios': [...], 'firmantes': [...]}.
    `conn` es del rol cirdan_retention (retencion.conectar())."""
    org, motivo = _uuid(org, 'La empresa'), _motivo(motivo)
    with conn.transaction():
        conn.execute("SET LOCAL TIME ZONE 'America/Mexico_City'")
        conn.execute("SELECT set_config('app.current_org', %s, true)", (org,))
        empresa = conn.execute('SELECT id::text, status, service_ended_at FROM organizations WHERE id = %s',
                               (org,)).fetchone()
        if not empresa:
            raise Error('No existe la empresa %s.' % org)
        conn.execute("UPDATE organizations SET status = 'cancelled', "
                     'service_ended_at = coalesce(service_ended_at, now()), updated_at = now() WHERE id = %s', (org,))
        conn.execute("UPDATE domains SET status = 'paused', updated_at = now() WHERE status <> 'removed'")
        usuarios = [f['id'] for f in conn.execute(
            'UPDATE users SET is_active = false, updated_at = now() RETURNING id::text').fetchall()]
        llaves = conn.execute('UPDATE api_keys SET revoked_at = now(), updated_at = now() '
                              'WHERE revoked_at IS NULL').rowcount
        filas = {}
        for tabla, condicion in BORRAR:
            sql, total = _sentencia(tabla, condicion), 0
            while True:
                borradas = conn.execute(sql, {'org': org, 'lote': LOTE}).rowcount
                total += borradas
                if borradas == 0 or (borradas < LOTE and tabla != 'assets'):
                    break
            filas[tabla] = total
        restan = {t: conn.execute('SELECT count(*) AS n FROM %s' % t).fetchone()['n']
                  for t in ('findings', 'assets', 'domain_scores', 'scans')}
        if any(restan.values()):
            raise Error('Quedaron filas sin borrar (%s): no se guardó nada.' % restan)
        firmantes = sorted({f['signer_email'] for f in conn.execute(
            'SELECT DISTINCT signer_email::text FROM domain_authorizations WHERE signer_email IS NOT NULL').fetchall()})
        conn.execute("INSERT INTO audit_log (organization_id, actor_type, action, details) "
                     "VALUES (%s, 'system', 'service.ended', %s)",
                     (org, Jsonb({'reason': motivo, 'previous_status': empresa['status'], 'rows': filas,
                                  'deactivated_users': len(usuarios), 'revoked_api_keys': llaves,
                                  'confirmation_to': len(firmantes)})))
    return {'filas': filas, 'usuarios': usuarios, 'firmantes': firmantes, 'llaves': llaves}


def confirmacion(nombre_empresa=None):
    """Asunto, texto y HTML de la confirmación a quien firmó: qué se borró y qué se conserva, sin datos de la empresa."""
    texto = ('Te confirmamos que terminó el servicio de LowTide para tu empresa y que borramos sus análisis: '
             'hallazgos, activos, scores, alertas y reportes.\n\n'
             'Conservamos la carta de autorización, las verificaciones del registro TXT y la bitácora, solo como prueba '
             'de lo que se hizo con tu autorización, durante el plazo de la sección 6 de la carta.\n\n'
             'Si no pediste esto o tienes dudas, responde a este correo.\n')
    pagina = ''.join('<p>%s</p>' % html.escape(p) for p in texto.strip().split('\n\n'))
    return ASUNTO, texto, pagina


def cancelar_usuario(conn, org, usuario, motivo):
    """Cancela la cuenta en la transacción de quien llama (`cirdan_app` con RLS de la empresa). Devuelve el resumen."""
    from cirdan.auth.demo import HASH_DE_RELLENO
    usuario, motivo = _uuid(usuario, 'El usuario'), _motivo(motivo)
    fila = conn.execute('SELECT id::text, cancelled_at FROM users WHERE id = %s FOR UPDATE', (usuario,)).fetchone()
    if not fila:
        raise Error('No existe el usuario %s en esa empresa.' % usuario)
    if fila['cancelled_at']:
        raise Error('La cuenta ya estaba cancelada desde %s.' % fila['cancelled_at'])
    conn.execute('UPDATE users SET password_hash = %s, totp_secret_enc = NULL, mfa_enabled_at = NULL, '
                 'last_totp_step = NULL, is_active = false, cancelled_at = now(), updated_at = now() WHERE id = %s',
                 (HASH_DE_RELLENO, usuario))
    passkeys = conn.execute('DELETE FROM webauthn_credentials WHERE user_id = %s', (usuario,)).rowcount
    llaves = conn.execute('UPDATE api_keys SET revoked_at = now(), updated_at = now() '
                          'WHERE created_by = %s AND revoked_at IS NULL', (usuario,)).rowcount
    conn.execute("INSERT INTO audit_log (organization_id, actor_type, action, entity_type, entity_id, details) "
                 "VALUES (%s, 'system', 'user.cancelled', 'user', %s, %s)",
                 (org, usuario, Jsonb({'reason': motivo, 'deleted_passkeys': passkeys, 'revoked_api_keys': llaves})))
    return {'usuario': usuario, 'passkeys': passkeys, 'llaves': llaves}


def _cerrar_sesiones(usuarios):
    from cirdan.auth import sessions
    for usuario in usuarios:
        try:
            sessions.delete_others(usuario, None)
        except Exception:   # sin Valkey las sesiones vencen solas en 8 h; la cuenta ya está inactiva
            log.warning('no se pudieron cerrar las sesiones de %s', usuario)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Fin del servicio y cancelación de cuentas (RC-258).')
    sub = parser.add_subparsers(dest='comando', required=True)
    t = sub.add_parser('terminar', help='borra los análisis de una empresa que terminó el servicio')
    t.add_argument('empresa')
    t.add_argument('--motivo', required=True)
    t.add_argument('--sin-correo', action='store_true', help='no manda la confirmación (pruebas)')
    c = sub.add_parser('cancelar-usuario', help='cancela una cuenta del portal')
    c.add_argument('usuario')
    c.add_argument('--organizacion', required=True)
    c.add_argument('--motivo', required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    try:
        if args.comando == 'terminar':
            with retencion.conectar() as conn:
                resultado = terminar(conn, args.empresa, args.motivo)
            _cerrar_sesiones(resultado['usuarios'])
            print('servicio terminado: %d filas borradas, %d cuentas desactivadas, %d llaves revocadas'
                  % (sum(resultado['filas'].values()), len(resultado['usuarios']), resultado['llaves']))
            if not args.sin_correo:
                from cirdan import correo
                for destino in resultado['firmantes']:
                    motivo = correo._enviar(destino, confirmacion(), 'la confirmación del fin de servicio')
                    print('confirmación a quien firmó: %s' % ('enviada' if motivo is None else 'no enviada (%s)' % motivo))
        else:
            from cirdan.db import transaction
            org = _uuid(args.organizacion, 'La empresa')
            with transaction(org) as conn:
                resultado = cancelar_usuario(conn, org, args.usuario, args.motivo)
            _cerrar_sesiones([resultado['usuario']])
            print('cuenta cancelada: %d passkeys borradas, %d llaves revocadas'
                  % (resultado['passkeys'], resultado['llaves']))
    except Error as error:
        print('error: %s' % error, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

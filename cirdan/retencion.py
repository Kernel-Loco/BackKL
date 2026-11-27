"""Retención de 12 meses (#139, RC-257): borra por lotes lo que pasa del plazo, empresa por empresa.

Corre con el rol `cirdan_retention` (migración 039), sin superusuario ni BYPASSRLS. Para cada empresa fija
`app.current_org`, así que la política `tenant_isolation` de cada tabla solo le deja ver y borrar esa empresa. Los
triggers de la 001 solo le dejan borrar `domain_scores` y `score_contributions` de más de 12 meses.

El orden es el de `db/cirdan_esquema.dbml` (nota de retención): primero lo que apunta a otras tablas y al final lo que
es apuntado. Cada paso borra solo filas que ya nadie referencia, así que una FK nunca hace fallar la corrida:

1. `deliveries` con `detected_at` de más de 12 meses.
2. `alerts` con `detected_at` de más de 12 meses y sin entregas.
3. `score_contributions` de scores calculados hace más de 12 meses.
4. `domain_scores` calculados hace más de 12 meses, sin aportes ni alertas.
5. `breach_exposures` de los hallazgos del paso 6.
6. `findings` resueltos hace más de 12 meses, sin aportes ni alertas. Un hallazgo abierto, en riesgo aceptado o
   marcado falso positivo no se borra por antigüedad: sigue vigente o es una etiqueta para el modelo (#80).
7. `assets` sin verse en 12 meses, sin hallazgos ni activos hijos (los hijos salen en una vuelta anterior del lote).
8. `reports` de más de 12 meses sin entregas. Hoy no se guarda el PDF: el reporte se arma al pedirlo.
9. `scan_source_runs` y 10. `scans` de más de 12 meses que ningún score referencia. `findings.last_scan_id` queda
   en NULL por su `ON DELETE SET NULL`.

`audit_log`, `domain_authorizations` y `dns_txt_verifications` no se tocan: su plazo queda como riesgo aceptado
(sección 9 de la política, RC-258).

Además anonimiza el nombre y el correo de las cuentas canceladas (`users.cancelled_at`, RC-258) cuando vence su plazo
(PLAZO_CANCELADAS). La huella de la contraseña y la semilla TOTP ya se borraron al cancelar (cirdan/fin_servicio.py).
La cadena de la bitácora no se rompe: solo guarda el id del actor.

Cada corrida deja en `audit_log` de cada empresa un evento `retention.purged` con cuántas filas borró por tabla, sin
datos de las filas.

    python -m cirdan.retencion              # servicio: corre al arrancar y cada 24 h
    python -m cirdan.retencion --una-vez    # una corrida y sale
"""
import argparse
import logging
import signal
import threading

import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from cirdan.config import config, required

log = logging.getLogger('cirdan.retencion')

PLAZO = "now() - interval '12 months'"
LOTE = 500
ACCION = 'retention.purged'
# Plazo de las cuentas canceladas antes de anonimizar su nombre y correo. Propuesta de RC-258: el mismo que los
# análisis (12 meses), mientras el equipo no decida otro [plazo] (sección 9 de la política).
PLAZO_CANCELADAS = "now() - interval '12 months'"
DOMINIO_ANONIMO = 'cancelada.invalid'
ANONIMIZAR_SQL = (
    "UPDATE users SET full_name = 'Cuenta cancelada', email = 'cancelada-' || id::text || '@" + DOMINIO_ANONIMO + "', "
    "updated_at = now() WHERE organization_id = %(org)s AND cancelled_at < " + PLAZO_CANCELADAS + " "
    "AND email::text NOT LIKE '%%@" + DOMINIO_ANONIMO + "'")

# (tabla, condición sobre las filas de la tabla, con alias t). Cada DELETE borra hasta LOTE filas a la vez.
PASOS = (
    ('deliveries', 't.detected_at < {plazo}'),
    ('alerts', 't.detected_at < {plazo} AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.alert_id = t.id)'),
    ('score_contributions', 't.score_id IN (SELECT s.id FROM domain_scores s WHERE s.computed_at < {plazo})'),
    ('domain_scores', 't.computed_at < {plazo} '
                      'AND NOT EXISTS (SELECT 1 FROM score_contributions c WHERE c.score_id = t.id) '
                      'AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.score_id = t.id)'),
    ('breach_exposures', 't.finding_id IN (SELECT f.id FROM findings f WHERE {hallazgo_viejo})'),
    ('findings', '{hallazgo_viejo_t} AND NOT EXISTS (SELECT 1 FROM breach_exposures b WHERE b.finding_id = t.id)'),
    ('assets', 't.last_seen_at < {plazo} '
               'AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = t.id) '
               'AND NOT EXISTS (SELECT 1 FROM assets h WHERE h.parent_asset_id = t.id)'),
    ('reports', 't.created_at < {plazo} AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.report_id = t.id)'),
    ('scan_source_runs', 't.scan_id IN (SELECT s.id FROM scans s WHERE {escaneo_viejo})'),
    ('scans', '{escaneo_viejo_t} AND NOT EXISTS (SELECT 1 FROM scan_source_runs r WHERE r.scan_id = t.id)'),
)

_HALLAZGO_VIEJO = ("{a}.status = 'resolved' AND {a}.resolved_at < {plazo} "
                   'AND NOT EXISTS (SELECT 1 FROM score_contributions c WHERE c.finding_id = {a}.id) '
                   'AND NOT EXISTS (SELECT 1 FROM alerts a2 WHERE a2.finding_id = {a}.id)')
_ESCANEO_VIEJO = ('{a}.queued_at < {plazo} AND NOT EXISTS (SELECT 1 FROM domain_scores ds WHERE ds.scan_id = {a}.id)')


def sentencia(tabla, condicion):
    """El DELETE de un lote de `tabla`. La empresa la pone RLS; el filtro por organization_id ayuda al índice."""
    llave = 'finding_id' if tabla == 'breach_exposures' else 'id'
    condicion = condicion.format(
        plazo=PLAZO,
        hallazgo_viejo=_HALLAZGO_VIEJO.format(a='f', plazo=PLAZO),
        hallazgo_viejo_t=_HALLAZGO_VIEJO.format(a='t', plazo=PLAZO),
        escaneo_viejo=_ESCANEO_VIEJO.format(a='s', plazo=PLAZO),
        escaneo_viejo_t=_ESCANEO_VIEJO.format(a='t', plazo=PLAZO))
    return ('DELETE FROM {t} WHERE {k} IN (SELECT t.{k} FROM {t} t WHERE t.organization_id = %(org)s AND {c} '
            'LIMIT %(lote)s)').format(t=tabla, k=llave, c=condicion)


SENTENCIAS = tuple((tabla, sentencia(tabla, condicion)) for tabla, condicion in PASOS)


def conectar():
    return psycopg.connect(make_conninfo(host=config('PGHOST', '127.0.0.1'), port=config('PGPORT', '5433'),
                                         dbname=config('PGDATABASE', 'cirdan'), user='cirdan_retention',
                                         password=required('CIRDAN_RETENTION_PASSWORD')),
                           row_factory=dict_row, autocommit=True)   # cada empresa, su propia transacción


def purgar_empresa(conn, org, lote=LOTE):
    """Borra lo vencido de una empresa en una transacción y deja su evento. Devuelve {tabla: filas}."""
    conteos = {}
    with conn.transaction():
        conn.execute("SET LOCAL TIME ZONE 'America/Mexico_City'")
        conn.execute("SELECT set_config('app.current_org', %s, true)", (str(org),))
        for tabla, sql in SENTENCIAS:
            total = 0
            while True:
                borradas = conn.execute(sql, {'org': str(org), 'lote': lote}).rowcount
                total += borradas
                if borradas < lote:
                    break
            conteos[tabla] = total
        conteos['users_anonymized'] = conn.execute(ANONIMIZAR_SQL, {'org': str(org)}).rowcount
        # Como cirdan.db.audit() con actor 'system'. No se importa cirdan.db: pide CIRDAN_APP_PASSWORD al cargarse y
        # este servicio no la tiene, a propósito.
        conn.execute("INSERT INTO audit_log (organization_id, actor_type, action, details) VALUES (%s, 'system', %s, %s)",
                     (str(org), ACCION, Jsonb({'plazo_meses': 12, 'filas': conteos, 'total': sum(conteos.values())})))
    return conteos


def empresas(conn):
    return [fila['retention_orgs'] for fila in conn.execute('SELECT retention_orgs()')]


def purgar(conn, organizacion=None, lote=LOTE):
    """Una corrida: todas las empresas, o solo `organizacion`. Devuelve {empresa: {tabla: filas}}."""
    objetivo = [organizacion] if organizacion else empresas(conn)
    return {str(org): purgar_empresa(conn, org, lote) for org in objetivo}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Retención de 12 meses (RC-257).')
    parser.add_argument('--una-vez', action='store_true')
    parser.add_argument('--organizacion', help='solo esta empresa (pruebas)')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    parada = threading.Event()
    for senal in (signal.SIGTERM, signal.SIGINT):
        signal.signal(senal, lambda *_: parada.set())
    while not parada.is_set():
        try:
            with conectar() as conn:
                resultado = purgar(conn, args.organizacion)
            total = sum(sum(c.values()) for c in resultado.values())
            log.info('retención aplicada: %d filas en %d empresas', total, len(resultado))
            espera = 86400
        except Exception:
            log.exception('falló la retención; se reintenta en una hora')
            if args.una_vez:
                return 1
            espera = 3600
        if args.una_vez:
            return 0
        parada.wait(espera)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

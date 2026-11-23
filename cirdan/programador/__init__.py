"""Escaneos programados (#27, RC-52): cada dominio autorizado se vuelve a escanear según plans.scan_interval.

Starter cada 7 días, Business y Enterprise cada día (semilla 001). Corre como servicio aparte (`python -m
cirdan.programador`, servicio `programador` de docker-compose.yml) con el rol cirdan_app, igual que la API, y da una
vuelta cada PROGRAMADOR_INTERVALO segundos (60 por omisión). En cada vuelta:

1. scheduled_scan_candidates() (migración 030) da los dominios que ya toca escanear, de todas las empresas: verified,
   de una empresa en trial o active, con carta no revocada y vigente y next_scan_at vacío o vencido. Solo da
   (organization_id, domain_id).
2. Por cada uno, en una transacción con app.current_org de su empresa, reclama el turno: mueve next_scan_at a
   `ahora + scan_interval` con FOR UPDATE SKIP LOCKED y solo si sigue vencido. Si otro proceso ya lo tomó o lo tiene
   tomado, reclama 0 filas y lo salta. En la misma transacción llama orquestador.solicitar(trigger='scheduled'), que
   revisa otra vez la carta, consulta el TXT en vivo (evidencia 'pre_scan') y crea el escaneo. El trigger
   scans_require_authorization y el índice único de un escaneo activo por dominio siguen de candados. Así el turno y
   el escaneo se confirman juntos o ninguno.
3. Si solicitar() lo rechaza (un escaneo a pedido en curso, TXT que ya no está, carta que venció hoy), queda
   auditado como cualquier rechazo y el siguiente intento va a `ahora + least(scan_interval, 1 día)`: con
   scan_in_progress tampoco se da el turno completo, porque el que corre puede fallar. Si algo lanza, la transacción
   se deshace y el siguiente intento va a una hora, en otra transacción.
4. Los aceptados corren en un hilo aparte después de confirmar, como en la API (cirdan/api/escaneos.py). A lo más
   PROGRAMADOR_MAX_ESCANEOS (2 por omisión, comentario 10262) a la vez en el proceso. Si el escaneo termina en
   'failed' (lanzó, ninguna fuente respondió, no se pudo lanzar o lo cerró detener()), el turno reclamado baja a
   `ahora + 1 hora` (least: nunca lo aleja), en vez de esperar el intervalo entero.

Un dominio fuera de DOMINIOS_EN_VIVO se salta sin auditar ni consultar: solicitar() lo rechazaría con
live_scan_not_allowed en cada vuelta. Su turno se pospone un día para que no ocupe el lote de cada vuelta. En la VM
DOMINIOS_EN_VIVO lleva la lista de los dominios con carta vigente (docs/despliegue.md).

Una sola instancia: __main__ toma un candado de sesión (pg_try_advisory_lock) en una conexión propia y sin él no da
vueltas. Si se encendieran dos, SKIP LOCKED y el índice único siguen evitando escaneos dobles.
"""
import logging
import threading
from contextlib import contextmanager
from datetime import timedelta

from cirdan import orquestador
from cirdan.config import config
from cirdan.db import transaction

log = logging.getLogger(__name__)

INTERVALO = 60          # segundos entre vueltas
MAX_ESCANEOS = 2        # escaneos programados a la vez en el proceso
LOTE = 100              # candidatos por vuelta
TOPE_RECHAZO = timedelta(days=1)    # un rechazo por carta o TXT se intenta otra vez a lo más en un día
ESPERA_ERROR = timedelta(hours=1)   # algo lanzó: se intenta otra vez en una hora
CANDADO = 'cirdan.programador'      # pg_try_advisory_lock(hashtext(CANDADO), 0): una sola instancia

CANDIDATOS_SQL = ('SELECT organization_id::text, domain_id::text '
                  'FROM scheduled_scan_candidates(coalesce(%s::timestamptz, now()), %s)')

# El turno se reclama solo si el dominio sigue verified y vencido. FOR UPDATE SKIP LOCKED: si otra transacción lo tiene
# tomado, esta no espera ni lo toma; si otra ya lo movió y confirmó, la condición deja de cumplirse. scan_interval sale
# del plan de la empresa de esa misma transacción (RLS de organizations).
RECLAMAR_SQL = '''
UPDATE domains d
   SET next_scan_at = coalesce(%(ahora)s::timestamptz, now()) + p.scan_interval
  FROM organizations o JOIN plans p ON p.id = o.plan_id
 WHERE d.id = (SELECT id FROM domains
                WHERE id = %(id)s AND status = 'verified'
                  AND (next_scan_at IS NULL OR next_scan_at <= coalesce(%(ahora)s::timestamptz, now()))
                  FOR UPDATE SKIP LOCKED)
   AND o.id = d.organization_id AND o.status IN ('trial', 'active')
RETURNING d.fqdn::text AS fqdn, p.scan_interval
'''
POSPONER_SQL = ('UPDATE domains SET next_scan_at = coalesce(%s::timestamptz, now()) '
                '+ least(%s::interval, %s::interval) WHERE id = %s')
# Un dominio fuera de DOMINIOS_EN_VIVO: sin reclamar ni auditar, solo se aparta un día del frente del lote. Mismo
# SKIP LOCKED y misma condición de vencido que RECLAMAR_SQL, así no espera ni pisa un turno que otro tomó.
APARTAR_SQL = '''
UPDATE domains SET next_scan_at = coalesce(%(ahora)s::timestamptz, now()) + %(espera)s::interval
 WHERE id = (SELECT id FROM domains
              WHERE id = %(id)s
                AND (next_scan_at IS NULL OR next_scan_at <= coalesce(%(ahora)s::timestamptz, now()))
                FOR UPDATE SKIP LOCKED)
'''
# El escaneo programado quedó en 'failed': el turno que reclamó baja a `ahora + espera`. least() nunca lo aleja, y si el
# escaneo terminó bien (completed o partial) no cambia nada.
REINTENTAR_SQL = '''
UPDATE domains d
   SET next_scan_at = least(d.next_scan_at, coalesce(%(ahora)s::timestamptz, now()) + %(espera)s::interval)
  FROM scans s
 WHERE s.id = %(scan)s AND s.domain_id = d.id AND s.status = 'failed'
'''

_hilos = {}               # scan_id -> (org, hilo) de los escaneos que lanzó este proceso
_hilos_candado = threading.Lock()


def _entero(nombre, defecto):
    valor = config(nombre)
    if valor in (None, ''):
        return defecto
    try:
        n = int(valor)
    except ValueError:
        raise ValueError('%s debe ser un entero mayor que 0' % nombre) from None
    if n < 1:
        raise ValueError('%s debe ser un entero mayor que 0' % nombre)
    return n


def intervalo():
    return _entero('PROGRAMADOR_INTERVALO', INTERVALO)


def max_escaneos():
    return _entero('PROGRAMADOR_MAX_ESCANEOS', MAX_ESCANEOS)


def en_curso():
    """Escaneos que este proceso lanzó y siguen corriendo."""
    with _hilos_candado:
        for scan_id, (_, hilo) in list(_hilos.items()):
            if not hilo.is_alive():
                del _hilos[scan_id]
        return len(_hilos)


def _reintentar_pronto(org, scan_id, ahora=None, conn=None):
    """Si el escaneo quedó en 'failed', su dominio se intenta otra vez en ESPERA_ERROR y no al siguiente turno."""
    try:
        with _en_empresa(org, conn) as c:
            c.execute(REINTENTAR_SQL, {'ahora': ahora, 'espera': ESPERA_ERROR, 'scan': scan_id})
    except Exception:
        log.exception('no se pudo adelantar el turno del escaneo %s', scan_id)


def _correr(org, scan_id, fqdn):
    try:
        orquestador.correr(org, scan_id, fqdn)
    except Exception as e:  # nunca dejar un escaneo en 'running' para siempre
        log.exception('el escaneo programado %s falló', scan_id)
        orquestador.marcar_fallido(org, scan_id, e)
    finally:
        _reintentar_pronto(org, scan_id)


def lanzar(org, scan_id, fqdn):
    hilo = threading.Thread(target=_correr, args=(org, scan_id, fqdn), name='programado-' + scan_id, daemon=True)
    with _hilos_candado:
        _hilos[scan_id] = (org, hilo)
    hilo.start()


def detener(motivo='El programador se detuvo antes de terminar el escaneo'):
    """Al apagar el servicio: los escaneos que siguen corriendo quedan en 'failed' en vez de esperar 30 minutos a que
    abandonar_vencidos() los dé por caídos (mientras tanto el dominio no aceptaría otro escaneo)."""
    with _hilos_candado:
        vivos = [(scan_id, org) for scan_id, (org, hilo) in _hilos.items() if hilo.is_alive()]
    for scan_id, org in vivos:
        try:
            orquestador.marcar_fallido(org, scan_id, RuntimeError(motivo))
        except Exception:
            log.exception('no se pudo cerrar el escaneo %s', scan_id)
        _reintentar_pronto(org, scan_id)


@contextmanager
def _tx(conn):
    if conn is not None:
        yield conn
    else:
        with transaction() as nueva:
            yield nueva


@contextmanager
def _en_empresa(org, conn):
    """Una transacción con app.current_org de la empresa o, con la conexión de una prueba, un punto de guardado en
    ella con la empresa fijada (un error deshace solo lo de este dominio)."""
    if conn is None:
        with transaction(org) as nueva:
            yield nueva
    else:
        with conn.transaction():
            conn.execute("SELECT set_config('app.current_org', %s, true)", (org,))
            yield conn


def _turno(org, domain_id, ahora, consultar, conn):
    """Reclama el turno del dominio y pide su escaneo en la misma transacción. None si no tocaba o no se consulta."""
    with _en_empresa(org, conn) as c:
        dominio = c.execute('SELECT fqdn::text FROM domains WHERE id = %s', (domain_id,)).fetchone()
        if not dominio:
            return None
        if consultar is None and not orquestador.en_vivo_permitido(dominio['fqdn']):
            c.execute(APARTAR_SQL, {'ahora': ahora, 'espera': TOPE_RECHAZO, 'id': domain_id})
            return None
        turno = c.execute(RECLAMAR_SQL, {'ahora': ahora, 'id': domain_id}).fetchone()
        if not turno:
            return None  # otro proceso lo tomó o ya no está vencido
        solicitud = orquestador.solicitar(org, turno['fqdn'], trigger='scheduled', consultar=consultar, conn=c)
        if not solicitud.aceptada:  # también scan_in_progress: el escaneo en curso puede fallar
            c.execute(POSPONER_SQL, (ahora, turno['scan_interval'], TOPE_RECHAZO, domain_id))
        return solicitud


def _posponer_por_error(org, domain_id, ahora, conn):
    try:
        with _en_empresa(org, conn) as c:
            c.execute(POSPONER_SQL, (ahora, ESPERA_ERROR, ESPERA_ERROR, domain_id))
    except Exception:
        log.exception('no se pudo posponer el dominio %s', domain_id)


def una_vuelta(ahora=None, consultar=None, lanzar_con=None, conn=None, tope=None, parada=None):
    """Pide los escaneos que ya tocan y devuelve las solicitudes (aceptadas y rechazadas) de los turnos reclamados.

    `ahora` es el reloj simulado de las pruebas (None: now() de la base). `consultar` reemplaza la consulta DNS,
    `lanzar_con` reemplaza el hilo que corre el escaneo y `conn` es la conexión de la prueba, que se deshace al final.
    `tope` reemplaza PROGRAMADOR_MAX_ESCANEOS. Con `parada` (threading.Event) puesta no empieza otro dominio: SIGTERM
    no espera a que se consulte el TXT de todo el lote.
    """
    lanzar_con = lanzar_con or lanzar
    cupo = (tope if tope is not None else max_escaneos()) - en_curso()
    solicitudes = []
    if cupo <= 0:
        return solicitudes
    with _tx(conn) as c:
        candidatos = c.execute(CANDIDATOS_SQL, (ahora, LOTE)).fetchall()
    for cand in candidatos:
        if cupo <= 0 or (parada is not None and parada.is_set()):
            break
        org, domain_id = cand['organization_id'], cand['domain_id']
        try:
            solicitud = _turno(org, domain_id, ahora, consultar, conn)
        except Exception:
            log.exception('falló el turno del dominio %s', domain_id)
            _posponer_por_error(org, domain_id, ahora, conn)
            continue
        if solicitud is None:
            continue
        solicitudes.append(solicitud)
        if solicitud.aceptada:
            log.info('escaneo programado %s del dominio %s', solicitud.scan_id, domain_id)
            cupo -= 1
            try:
                lanzar_con(org, solicitud.scan_id, solicitud.fqdn)
            except Exception as e:  # sin hilo nadie lo cerraría: que no quede en 'running'
                log.exception('no se pudo lanzar el escaneo %s', solicitud.scan_id)
                try:
                    orquestador.marcar_fallido(org, solicitud.scan_id, e)
                except Exception:
                    log.exception('no se pudo cerrar el escaneo %s', solicitud.scan_id)
                _reintentar_pronto(org, solicitud.scan_id, ahora, conn)
        else:
            log.info('escaneo programado rechazado del dominio %s: %s', domain_id, ', '.join(solicitud.motivos))
    return solicitudes

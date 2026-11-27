"""Servicio de escaneos programados (#27, RC-52): una vuelta cada PROGRAMADOR_INTERVALO segundos.

    python -m cirdan.programador            # el servicio, hasta SIGTERM o Ctrl+C
    python -m cirdan.programador --una-vez  # una sola vuelta, espera a sus escaneos y sale (código 0)

Con Docker: docker compose --profile programador up -d programador. No se enciende con `docker compose up -d`
(profiles en docker-compose.yml) salvo con COMPOSE_PROFILES=programador en el .env, como en la VM (docs/despliegue.md,
'Escaneos programados'): al encenderlo salen en el acto los dominios con next_scan_at vacío o vencido.

Solo da vueltas mientras tiene el candado de sesión CANDADO en su propia conexión. Si otro programador lo tiene, espera
y lo vuelve a intentar en cada vuelta. Si la conexión del candado se cae, la cierra y lo vuelve a tomar.
"""
import argparse
import logging
import signal
import sys
import threading

import psycopg

from cirdan import programador
from cirdan.db import DSN
from cirdan.proceso import no_volcable

log = logging.getLogger('cirdan.programador')


def tomar_candado():
    """Una conexión con el candado del programador o None si otro lo tiene."""
    conn = psycopg.connect(DSN, autocommit=True, keepalives=1, keepalives_idle=30, keepalives_interval=10,
                           keepalives_count=3)
    try:
        tomado = conn.execute('SELECT pg_try_advisory_lock(hashtext(%s), 0)', (programador.CANDADO,)).fetchone()[0]
    except Exception:
        conn.close()
        raise
    if not tomado:
        conn.close()
        return None
    return conn


def sigue_vivo(conn):
    try:
        conn.execute('SELECT 1')
        return True
    except psycopg.Error:
        return False


def main(argv=None):
    p = argparse.ArgumentParser(prog='python -m cirdan.programador', description='Pide los escaneos programados.')
    p.add_argument('--una-vez', action='store_true', help='una sola vuelta y sale')
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    # Antes de la primera vuelta: git y gitleaks corren con el mismo uid y sin esto leerían este entorno (RC-324).
    no_volcable()
    espera = programador.intervalo()
    programador.max_escaneos()  # un valor mal escrito tumba el arranque, no la primera vuelta

    parada = threading.Event()
    for senal in (signal.SIGTERM, signal.SIGINT):
        signal.signal(senal, lambda *_: parada.set())

    candado, avisado = None, False
    try:
        while not parada.is_set():
            try:
                if candado is not None and not sigue_vivo(candado):
                    log.warning('se perdió la conexión del candado')
                    candado.close()
                    candado = None
                if candado is None:
                    candado = tomar_candado()
                    if candado is None and not avisado:
                        log.warning('otro programador tiene el candado: esta instancia espera')
                    avisado = candado is None
                if candado is not None:
                    programador.una_vuelta(parada=parada)
            except Exception:
                log.exception('falló la vuelta del programador')
            if args.una_vez:
                while programador.en_curso() and not parada.is_set():  # que terminen los escaneos que lanzó
                    parada.wait(5)
                break
            parada.wait(espera)
    finally:
        programador.detener()
        if candado is not None:
            candado.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())

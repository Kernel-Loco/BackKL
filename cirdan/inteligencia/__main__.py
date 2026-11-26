"""Servicio de carga de inteligencia: `python -m cirdan.inteligencia [--una-vez]`."""
import argparse
import logging
import signal
import threading

from cirdan import inteligencia

log = logging.getLogger('cirdan.inteligencia')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Actualiza CISA KEV y FIRST EPSS.')
    parser.add_argument('--una-vez', action='store_true')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    parada = threading.Event()
    for senal in (signal.SIGTERM, signal.SIGINT):
        signal.signal(senal, lambda *_: parada.set())
    while not parada.is_set():
        try:
            with inteligencia.conexion() as conn:
                total, kev, epss = inteligencia.actualizar(conn)
            log.info('inteligencia actualizada: %d CVE, %d KEV, %d EPSS', total, kev, epss)
            espera = 86400
        except Exception:
            log.exception('falló la carga de inteligencia; se conservan los datos anteriores')
            if args.una_vez:
                return 1
            espera = 3600
        if args.una_vez:
            return 0
        parada.wait(espera)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

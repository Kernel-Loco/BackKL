"""Reintenta a mano las entregas de alertas vencidas de una empresa (RC-114): `python -m cirdan.alertas <empresa>`.

Sirve si el proceso que despachaba se reinició antes de terminar sus reintentos: las entregas siguen en la base.
"""
import argparse
import logging

from cirdan.alertas import outbox


def main(argv=None):
    parser = argparse.ArgumentParser(description='Manda las entregas de alertas pendientes de una empresa.')
    parser.add_argument('organizacion', help='id de la empresa')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    intentadas = outbox.despachar(args.organizacion)
    print('entregas intentadas: %d' % intentadas)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

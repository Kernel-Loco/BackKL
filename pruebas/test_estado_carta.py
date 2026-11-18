"""Estado de la carta en GET /api/v1/domains con la fecha de la base (RC-313), sin base ni red.

La base corre con la zona de México (cirdan/db.py) y DOMAINS_SQL decide con su current_date si la carta está vigente
(auth_valid) o aún no empieza (auth_not_started). El contenedor de la API va en UTC: de 18:00 a 24:00 de México su
date.today() ya es el día siguiente. Estas pruebas fijan ese reloj (date y datetime de cirdan.api.v1) en el día de
inicio de la carta y revisan que _domain siga lo que dijo la base. test_5 revisa además que _domain no lea ningún
reloj, así una vuelta a datetime.now() o a time falla a cualquier hora. Importan cirdan.api.v1, así que corren dentro
del contenedor:

    docker compose run --rm -e ESTADO_CARTA=1 -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_estado_carta.py

Fuera del contenedor, sin FastAPI o sin el .env, se saltan. Con ESTADO_CARTA=1 fallan en vez de saltarse.
"""
import os
import unittest
from datetime import date, datetime, timedelta, timezone
from unittest import mock

HOY_MEXICO = date(2026, 11, 17)          # 20:00 de México
MANANA = HOY_MEXICO + timedelta(days=1)  # 02:00 UTC del día siguiente, lo que ve date.today() en la API


def _api():
    try:
        from cirdan.api import v1
    except (ImportError, RuntimeError) as e:  # RuntimeError: sin las variables del .env (config.required)
        if os.environ.get('ESTADO_CARTA') == '1':
            raise
        raise unittest.SkipTest('Sin FastAPI, psycopg, dnspython o .env: corre dentro del contenedor (%s)' % e)
    return v1


class FechaUTC(date):
    """date.today() del contenedor en UTC cuando en México son las 20:00."""

    @classmethod
    def today(cls):
        return cls(MANANA.year, MANANA.month, MANANA.day)


class FechaHoraUTC(datetime):
    """datetime.now() y datetime.today() del contenedor en UTC cuando en México son las 20:00."""

    @classmethod
    def now(cls, tz=None):
        utc = cls(MANANA.year, MANANA.month, MANANA.day, 2, 0, tzinfo=timezone.utc)
        return utc.astimezone(tz) if tz else utc.replace(tzinfo=None)

    @classmethod
    def today(cls):
        return cls.now()

    @classmethod
    def utcnow(cls):
        return cls.now()


def _nombres(code):
    """Nombres globales y atributos que usa una función, también dentro de sus funciones internas."""
    nombres = set(code.co_names)
    for c in code.co_consts:
        if hasattr(c, 'co_names'):
            nombres |= _nombres(c)
    return nombres


def fila(**cambios):
    r = {'id': 'd1', 'fqdn': 'acme-demo.mx', 'status': 'active', 'last_scan_at': None, 'next_scan_at': None,
         'valid_from': MANANA, 'valid_until': MANANA + timedelta(days=365), 'revoked_at': None,
         'signer_email': 'ti@acme-demo.mx', 'auth_valid': False, 'auth_not_started': True,
         'txt_result': 'match', 'txt_checked_at': None, 'score': None, 'open_findings': None}
    r.update(cambios)
    return r


class Estado(unittest.TestCase):

    def estado(self, r):
        v1 = _api()
        with mock.patch.object(v1, 'date', FechaUTC), mock.patch.object(v1, 'datetime', FechaHoraUTC):
            d = v1._domain(r)
        return d['authorization']['status'], d['scan_eligibility']['reasons']

    def test_1_carta_que_empieza_manana_sale_missing_nunca_expired(self):
        self.assertEqual(self.estado(fila()), ('missing', ['authorization_not_started']))

    def test_2_carta_vencida_sale_expired(self):
        r = fila(valid_from=date(2025, 11, 17), valid_until=HOY_MEXICO - timedelta(days=1), auth_not_started=False)
        self.assertEqual(self.estado(r), ('expired', ['authorization_expired']))

    def test_3_vigente_sin_carta_y_revocada(self):
        self.assertEqual(self.estado(fila(valid_from=HOY_MEXICO, auth_valid=True, auth_not_started=False)),
                         ('valid', []))
        self.assertEqual(self.estado(fila(valid_from=None, valid_until=None, auth_not_started=None)),
                         ('missing', ['authorization_missing']))
        self.assertEqual(self.estado(fila(revoked_at='2026-11-17T20:00:00-06:00')),
                         ('revoked', ['authorization_revoked']))

    def test_4_domains_sql_da_si_la_carta_aun_no_empieza(self):
        v1 = _api()
        self.assertIn('(a.valid_from > current_date) AS auth_not_started', v1.DOMAINS_SQL)

    def test_5_domain_no_lee_ningun_reloj(self):
        # El mock de arriba solo cubre date y datetime de cirdan.api.v1. Si _domain vuelve a leer la hora por otro
        # camino, fuera de 18:00 a 24:00 de México ninguna prueba lo notaría.
        v1 = _api()
        reloj = {'date', 'datetime', 'today', 'now', 'utcnow', 'time', 'monotonic', 'localtime', 'gmtime'}
        self.assertEqual(_nombres(v1._domain.__code__) & reloj, set())


if __name__ == '__main__':
    unittest.main()

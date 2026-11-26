"""Cargador de inteligencia RC-127; sin consultar servicios externos."""
import os
import gzip
import unittest
from datetime import date, datetime, timezone
from decimal import Decimal
from unittest.mock import patch

import psycopg

from cirdan import inteligencia


def kev(*ids):
    return {'count': len(ids), 'vulnerabilities': [
        {'cveID': cve, 'dateAdded': '2026-01-02'} for cve in ids]}


def epss(*ids):
    hoy = datetime.now(timezone.utc).date()
    datos = '#model_version:v5,score_date:%sT12:00:23Z\ncve,epss,percentile\n' % hoy
    datos += ''.join('%s,0.12345,0.99999\n' % cve for cve in ids)
    return gzip.compress(datos.encode())


class Lectura(unittest.TestCase):
    def test_kev_valido_y_fecha(self):
        self.assertEqual(inteligencia.leer_kev(kev('CVE-2024-1234')), {'CVE-2024-1234': date(2026, 1, 2)})

    def test_kev_incompleto_invalido_o_repetido(self):
        for datos in ({'count': 1, 'vulnerabilities': []}, kev('CVE-2024-1234', 'CVE-2024-1234'),
                      kev('no-cve'), {'count': 1, 'vulnerabilities': [{'cveID': 'CVE-2024-1234',
                                                                     'dateAdded': '2026-02-30'}]}):
            with self.subTest(datos=datos), self.assertRaises(ValueError):
                inteligencia.leer_kev(datos)

    def test_epss_valido_y_cve_sin_puntaje(self):
        self.assertEqual(inteligencia.leer_epss(epss('CVE-2024-1234'), {'CVE-2024-1234', 'CVE-2024-5678'}),
                         {'CVE-2024-1234': (Decimal('0.12345'), Decimal('0.99999'))})

    def test_epss_incompleto_o_invalido(self):
        casos = [epss(), epss('CVE-2024-1234', 'CVE-2024-1234'), b'no-gzip',
                 gzip.compress(b'#model_version:v5,score_date:2000-01-01\ncve,epss,percentile\nCVE-2024-1234,0.2,0.3\n')]
        for valor in ('NaN', '1.1', '-0.1', None):
            datos = gzip.decompress(epss('CVE-2024-1234')).decode().replace('0.12345', str(valor))
            casos.append(gzip.compress(datos.encode()))
        for datos in casos:
            with self.subTest(datos=datos), self.assertRaises((ValueError, OSError)):
                inteligencia.leer_epss(datos, {'CVE-2024-1234'})


@unittest.skipUnless(os.environ.get('INTEL_TEST_DSN'), 'requiere base aislada INTEL_TEST_DSN')
class BaseAislada(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg.connect(os.environ['INTEL_TEST_DSN'])

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def test_carga_atomica_y_permisos(self):
        a, b, c = 'CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-10003'
        self.conn.execute('INSERT INTO cves (cve_id, in_kev) VALUES (%s, true)', (a,))

        self.assertEqual(inteligencia.actualizar(self.conn, lambda *_: kev(b), lambda: epss(a, b)), (2, 1, 2))
        filas = self.conn.execute('SELECT cve_id, in_kev, kev_date_added, epss_score, intel_updated_at '
                                  'FROM cves ORDER BY cve_id').fetchall()
        self.assertEqual([(r[0], r[1], r[2], r[3]) for r in filas],
                         [(a, False, None, Decimal('0.12345')), (b, True, date(2026, 1, 2), Decimal('0.12345'))])
        self.assertTrue(all(r[4] is not None for r in filas))

        with self.assertRaises(OSError):
            inteligencia.actualizar(self.conn, lambda *_: kev(c), lambda: b'no-gzip')
        self.assertEqual(self.conn.execute('SELECT cve_id, in_kev, kev_date_added, epss_score, intel_updated_at '
                                           'FROM cves ORDER BY cve_id').fetchall(), filas)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.conn.execute('UPDATE cves SET cvss_base_score = 10 WHERE cve_id = %s', (a,))

    def test_candado_impide_dos_cargas(self):
        otra = psycopg.connect(os.environ['INTEL_TEST_DSN'], autocommit=True)
        try:
            otra.execute('SELECT pg_advisory_lock(hashtext(%s), 0)', (inteligencia.CANDADO,))
            with patch.object(inteligencia, 'descargar_json') as descarga:
                with self.assertRaisesRegex(RuntimeError, 'otro cargador'):
                    inteligencia.actualizar(self.conn, descarga, descarga)
                descarga.assert_not_called()
        finally:
            otra.close()


if __name__ == '__main__':
    unittest.main()

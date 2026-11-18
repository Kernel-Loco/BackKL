"""Pruebas sin red del reporte ejecutivo (cirdan/reporte.py, #45, RC-70).

Uso, desde la raíz del repo:
  python -m unittest pruebas/test_reporte.py

La ruta, el 403 sin carta vigente y la descarga en HTML se prueban contra la API en test_api_v1.py (test_9f).
Ruta importa la API (FastAPI, psycopg y dnspython) y corre dentro del contenedor, como pruebas.test_rdap.Transporte:
  docker compose run --rm -e RUTA_REPORTE=1 -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest pruebas.test_reporte.Ruta
Fuera del contenedor se salta. RUTA_REPORTE=1 hace que falle si no puede importar la API.
"""
import os
import re
import sys
import unittest
from contextlib import contextmanager
from datetime import date, datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cirdan import reporte  # noqa: E402

AHORA = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
SEV = ('critical', 'high', 'medium', 'low')


def hallazgo(i, severidad='high', categoria='configuration', regla='dmarc_missing', titulo=None, recurrencia='new',
             activo=None, tipo='subdomain'):
    return {'id': 'f%d' % i, 'title': titulo or 'Hallazgo %d' % i, 'severity': severidad, 'category': categoria,
            'rule_code': regla, 'asset': activo or 'a%d.olmardo.com' % i, 'asset_type': tipo, 'source': 'dns',
            'detected_at': datetime(2026, 11, 3, tzinfo=timezone.utc), 'recurrence': recurrencia}


def armar(hallazgos, recomendaciones=None, score=None):
    score = score or {'score': 64, 'band': 'high', 'grade': 'D', 'partial_coverage': False, 'computed_at': AHORA}
    return reporte.armar('olmardo.com', 'Grupo Olmardo', {'valid_from': date(2026, 10, 13), 'valid_until': date(2027, 10, 13)},
                         score, AHORA, hallazgos, recomendaciones or {}, generado=AHORA)


class Armado(unittest.TestCase):

    def test_1_cuenta_todos_y_lista_solo_los_mas_severos(self):
        hs = [hallazgo(i, SEV[i % 4]) for i in range(20)]
        r = armar(hs)
        self.assertEqual(r['total_open'], 20)
        self.assertEqual(r['open_findings'], {'critical': 5, 'high': 5, 'medium': 5, 'low': 5})
        self.assertEqual(sum(r['by_category'].values()), 20)
        self.assertEqual(len(r['findings']), reporte.MAX_HALLAZGOS)
        self.assertEqual(r['findings_omitted'], 20 - reporte.MAX_HALLAZGOS)
        self.assertEqual([h['title'] for h in r['findings']], ['Hallazgo %d' % i for i in range(reporte.MAX_HALLAZGOS)])

    def test_2_la_accion_es_la_primera_frase_con_tope(self):
        r = armar([hallazgo(1)], {'dmarc_missing': 'Publica DMARC con p=none. Luego súbelo a reject.'})
        self.assertEqual(r['findings'][0]['action'], 'Publica DMARC con p=none.')
        largo = reporte.accion_corta('x' * 500)
        self.assertEqual(len(largo), reporte.MAX_ACCION)
        self.assertTrue(largo.endswith('…'))
        self.assertEqual(reporte.accion_corta(None), '')

    def test_3_siempre_trae_la_atribucion_de_hibp(self):
        for hs in ([], [hallazgo(1, categoria='data_leaks', regla='breach_exposure')]):
            r = armar(hs)
            hibp = [a for a in r['attributions'] if a['source'] == 'hibp']
            self.assertEqual(len(hibp), 1)
            self.assertIn('Have I Been Pwned', hibp[0]['text'])
            self.assertIn('CC BY 4.0', hibp[0]['text'])
            self.assertIn('Have I Been Pwned', reporte.html(r))

    def test_4_sin_hallazgos_lo_dice_sin_inventar_cifras(self):
        r = armar([])
        self.assertEqual(r['findings'], [])
        self.assertEqual(reporte.lectura(r), ['El dominio no tiene hallazgos abiertos.'])

    def test_5_un_correo_sale_solo_con_su_dominio(self):
        # Como la salida a SIEM, que anula los activos de tipo email: el reporte se comparte fuera del portal.
        r = armar([hallazgo(1, regla='email_in_public_commits', activo='juan.perez@olmardo.com', tipo='email'),
                   hallazgo(2, activo='raro-sin-arroba', tipo='email'), hallazgo(3)])
        self.assertEqual([h['asset'] for h in r['findings']], ['Correo de olmardo.com', 'Correo', 'a3.olmardo.com'])
        self.assertNotIn('juan.perez', reporte.html(r))
        self.assertNotIn('raro-sin-arroba', reporte.html(r))

    def test_6_titulo_y_activo_con_tope(self):
        # Sin tope, 8 títulos o activos muy largos abren una tercera página en el PDF del portal.
        r = armar([hallazgo(i, titulo='CVE-2026-%04d ' % i * 80, activo='n%d.' % i * 200 + 'olmardo.com')
                   for i in range(reporte.MAX_HALLAZGOS)])
        for h in r['findings']:
            self.assertEqual(len(h['title']), reporte.MAX_TITULO)
            self.assertEqual(len(h['asset']), reporte.MAX_ACTIVO)
            self.assertTrue(h['title'].endswith('…') and h['asset'].endswith('…'))
        self.assertEqual(armar([hallazgo(1, titulo='Corto')])['findings'][0]['title'], 'Corto')

    def test_7_generado_en_la_hora_de_mexico(self):
        # El contenedor corre en UTC: a las 19:00 de México el HTML decía el día siguiente y el PDF no.
        r = reporte.armar('olmardo.com', 'Grupo Olmardo', {}, None, None, [], {})
        self.assertEqual(getattr(r['generated_at'].tzinfo, 'key', None), 'America/Mexico_City')
        noche = datetime(2026, 11, 16, 1, 0, tzinfo=timezone.utc)  # 19:00 del 15 nov en México

        class Reloj(datetime):
            @classmethod
            def now(cls, tz=None):
                return noche.astimezone(tz) if tz else noche.replace(tzinfo=None)

        with mock.patch.object(reporte, 'datetime', Reloj):
            r = reporte.armar('olmardo.com', 'Grupo Olmardo', {}, None, None, [], {})
        self.assertIn('Generado: 15/11/2026', reporte.html(r))

    def test_8_nuevos_desde_su_ultimo_escaneo_no_del_dominio(self):
        # recurrence se calcula contra el último escaneo de cada hallazgo, no el último del dominio (FINDINGS_SQL).
        frases = reporte.lectura(armar([hallazgo(1), hallazgo(2, recurrencia='recurring')]))
        self.assertIn('1 de los 2 hallazgos abiertos son nuevos en el escaneo más reciente que los revisó.', frases)
        self.assertFalse(any('aparecieron en el último escaneo' in f for f in frases))


class Html(unittest.TestCase):

    def test_1_escapa_todo_lo_que_viene_de_la_base(self):
        malo = '<script>alert(1)</script>"\'&'
        r = armar([hallazgo(1, titulo=malo)], {'dmarc_missing': '<img src=x onerror=alert(1)>'})
        r['organization'] = '<b>Org</b>'
        texto = reporte.html(r)
        self.assertNotIn('<script', texto)
        self.assertNotIn('<img', texto)
        self.assertNotIn('<b>Org', texto)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#x27;&amp;', texto)

    def test_2_el_html_trae_lo_mismo_que_el_json(self):
        hs = [hallazgo(i, SEV[i % 4]) for i in range(10)]
        r = armar(hs, {'dmarc_missing': 'Publica DMARC.'})
        texto = reporte.html(r)
        for h in r['findings']:
            self.assertIn(h['title'], texto)
            self.assertIn(h['asset'], texto)
        self.assertNotIn('Hallazgo 9<', texto)  # el noveno y el décimo van en el conteo, no en la lista
        self.assertIn('Y 2 hallazgos abiertos más', texto)
        self.assertIn('64, letra D (Alto)', texto)
        self.assertIn('13/10/2026 a 13/10/2027', texto)
        for frase in reporte.lectura(r):
            self.assertIn(frase, texto)

    def test_3_sin_recursos_externos_ni_scripts(self):
        texto = reporte.html(armar([hallazgo(1)]))
        self.assertTrue(texto.startswith('<!doctype html>'))
        self.assertIsNone(re.search(r'<(script|link|img|iframe)\b', texto))
        self.assertIsNone(re.search(r'\b(src)=', texto))
        self.assertIn("default-src 'none'", reporte.CSP_HTML)
        self.assertIn("frame-ancestors 'none'", reporte.CSP_HTML)

    def test_4_cobertura_parcial_lleva_el_aviso(self):
        r = armar([], score={'score': 30, 'band': 'low', 'grade': 'B', 'partial_coverage': True, 'computed_at': AHORA})
        self.assertIn('Cobertura parcial', reporte.html(r))


def _api():
    try:
        from cirdan.api import v1
    except (ImportError, RuntimeError) as e:  # RuntimeError: sin las variables del .env (config.required)
        if os.environ.get('RUTA_REPORTE') == '1':
            raise
        raise unittest.SkipTest('Sin FastAPI, psycopg, dnspython o .env: corre dentro del contenedor (%s)' % e)
    return v1


class Ruta(unittest.TestCase):

    def test_1_una_sola_foto_con_repeatable_read(self):
        # En READ COMMITTED un escaneo que cierra entre SCORES_SQL y FINDINGS_SQL mezcla el score de uno con los
        # hallazgos del otro. La salida a SIEM ya fija REPEATABLE_READ.
        v1 = _api()
        llamadas = []

        class Conn:
            def execute(self, sql, params=None):
                fila = {'last_scan_at': None, 'organization': 'Acme', 'valid_from': date(2026, 1, 1),
                        'valid_until': date(2027, 1, 1)}
                return SimpleNamespace(fetchone=lambda: fila, fetchall=lambda: [])

        @contextmanager
        def transaccion(org=None, isolation=None):
            llamadas.append(isolation)
            yield Conn()

        with mock.patch.object(v1, '_dominio_autorizado', return_value='d1'), \
                mock.patch.object(v1, 'transaction', transaccion):
            r = v1._reporte(SimpleNamespace(org_id='o1'), 'acme-demo.mx')
        self.assertEqual(llamadas, [v1.IsolationLevel.REPEATABLE_READ])
        self.assertEqual(r['organization'], 'Acme')

    def test_2_la_bitacora_no_va_en_repeatable_read(self):
        # Por eso el reporte no registra aún su descarga (RC-312): en REPEATABLE READ el trigger de la cadena lee el
        # último eslabón con la foto vieja y dos descargas a la vez chocan en chain_seq. audit() lo rechaza antes.
        v1 = _api()
        from cirdan import db
        for nivel in (v1.IsolationLevel.REPEATABLE_READ, v1.IsolationLevel.SERIALIZABLE):
            conn = SimpleNamespace(isolation_level=nivel, execute=mock.Mock())
            with self.assertRaises(ValueError):
                db.audit(conn, 'o1', 'report.downloaded')
            conn.execute.assert_not_called()
        for nivel in (None, v1.IsolationLevel.READ_COMMITTED):
            conn = SimpleNamespace(isolation_level=nivel, execute=mock.Mock())
            db.audit(conn, 'o1', 'report.downloaded')
            conn.execute.assert_called_once()


if __name__ == '__main__':
    unittest.main()

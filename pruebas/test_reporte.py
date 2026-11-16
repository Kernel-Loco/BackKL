"""Pruebas sin red del reporte ejecutivo (cirdan/reporte.py, #45, RC-70).

Uso, desde la raíz del repo:
  python -m unittest pruebas/test_reporte.py

La ruta, el 403 sin carta vigente y la descarga en HTML se prueban contra la API en test_api_v1.py (test_9f).
"""
import re
import sys
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cirdan import reporte  # noqa: E402

AHORA = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
SEV = ('critical', 'high', 'medium', 'low')


def hallazgo(i, severidad='high', categoria='configuration', regla='dmarc_missing', titulo=None, recurrencia='new'):
    return {'id': 'f%d' % i, 'title': titulo or 'Hallazgo %d' % i, 'severity': severidad, 'category': categoria,
            'rule_code': regla, 'asset': 'a%d.olmardo.com' % i, 'source': 'dns',
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


if __name__ == '__main__':
    unittest.main()

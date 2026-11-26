"""Medición de cobertura y falsos positivos (#84, RC-143), sin base ni red.

    python -m unittest -v pruebas/test_medicion.py
"""
import re
import unittest
from datetime import date
from pathlib import Path

from cirdan import medicion

RAIZ = Path(__file__).resolve().parents[1]
TODAS = {e.fuente: 'succeeded' for e in medicion.ESPERADOS}
NOV = date(2026, 11, 26)


def h(codigo, activo, fuente, estado='open'):
    return {'rule_code': codigo, 'asset': activo, 'source': fuente, 'status': estado}


SIEMBRA_VISTA = [
    h('cert_broad_wildcard', 'olmardo.com', 'ct_logs'),
    h('dmarc_missing', 'olmardo.com', 'dns'),
    h('secret_in_public_repo', 'olmardo.com', 'github'),
    h('email_in_public_commits', 'equipo@olmardo.com', 'github'),
    h('exposed_service', '20.69.154.199:8080/tcp', 'shodan'),
    h('server_version_disclosed', 'reservas.olmardo.com', 'web'),
]


class Medir(unittest.TestCase):

    def test_1_todo_visto_con_fuentes_completas(self):
        m = medicion.medir(SIEMBRA_VISTA, TODAS, NOV)
        resultados = {c['esperado'].fila: c['resultado'] for c in m['casos']}
        self.assertEqual(resultados, {3: 'VP', 5: 'fuera de vigencia', 6: 'VP', 8: 'VP', 9: 'VP', 10: 'VP', 11: 'FN',
                                      12: 'VP'})
        self.assertEqual(m['total'], {'VP': 6, 'FN': 1, 'no_evaluables': 1, 'detectado_pct': 85.7})
        self.assertEqual(m['por_fuente']['shodan'], {'VP': 1, 'FN': 1, 'no_evaluables': 0, 'detectado_pct': 50.0})
        self.assertEqual(m['inesperados'], [])

    def test_2_una_fuente_caida_no_cuenta_como_falso_negativo(self):
        corridas = dict(TODAS, github='failed')
        del corridas['web']
        m = medicion.medir([x for x in SIEMBRA_VISTA if x['source'] not in ('github', 'web')], corridas, NOV)
        resultados = {c['esperado'].fila: c['resultado'] for c in m['casos']}
        self.assertEqual((resultados[8], resultados[9], resultados[12]),
                         ('sin cobertura (failed)', 'sin cobertura (failed)', 'sin cobertura (no corrió)'))
        self.assertEqual(m['por_fuente']['github']['detectado_pct'], None)   # no evaluable, nunca 0
        self.assertEqual(m['total']['FN'], 1)

    def test_3_el_mismo_codigo_en_otro_activo_no_es_acierto(self):
        m = medicion.medir([h('dmarc_missing', 'otro.com', 'dns')], TODAS, NOV)
        fila6 = next(c for c in m['casos'] if c['esperado'].fila == 6)
        self.assertEqual(fila6['resultado'], 'FN')

    def test_4_el_certificado_de_eventos_cuenta_solo_en_su_ventana(self):
        caso = [h('cert_expiring_soon', 'eventos.olmardo.com', 'ct_logs')]
        en_ventana = medicion.medir(caso, TODAS, date(2026, 10, 30))
        self.assertEqual(next(c for c in en_ventana['casos'] if c['esperado'].fila == 5)['resultado'], 'VP')
        sin_verlo = medicion.medir([], TODAS, date(2026, 10, 30))
        self.assertEqual(next(c for c in sin_verlo['casos'] if c['esperado'].fila == 5)['resultado'], 'FN')

    def test_5_falsos_positivos_entre_los_revisados_con_el_triage(self):
        hallazgos = SIEMBRA_VISTA + [h('lookalike_domain', 'olmard0.com', 'ct_logs', 'false_positive'),
                                     h('exposed_service', '20.69.154.199:50000/tcp', 'shodan', 'false_positive'),
                                     h('dmarc_missing', 'olmardo.com', 'dns', 'resolved'),
                                     h('spf_missing', 'olmardo.com', 'dns', 'accepted_risk')]
        m = medicion.medir(hallazgos, TODAS, NOV)
        self.assertEqual(m['falsos_positivos'], {'revisados': 4, 'falsos': 2, 'proporcion_pct': 50.0})
        self.assertIn(('ct_logs', 'lookalike_domain', 'olmard0.com'), m['inesperados'])
        self.assertEqual(medicion.medir(SIEMBRA_VISTA, TODAS, NOV)['falsos_positivos']['proporcion_pct'], None)

    def test_6_el_markdown_dice_de_que_escaneo_sale_y_no_inventa_ceros(self):
        texto = medicion.markdown(medicion.medir([], {}, NOV), 'olmardo.com',
                                  {'id': 'abc', 'fecha': NOV, 'status': 'partial'})
        self.assertIn('escaneo abc de olmardo.com (2026-11-26, partial)', texto)
        self.assertIn('no evaluable', texto)
        self.assertNotIn('0 %', texto)
        self.assertIn('requiere la API de host de Shodan', texto)


class ListaEsperada(unittest.TestCase):

    def test_1_cada_caso_esta_en_su_fila_de_hallazgos_esperados_con_su_codigo(self):
        texto = (RAIZ / 'docs' / 'hallazgos_esperados.md').read_text(encoding='utf-8')
        filas = {int(n): fila for n, fila in re.findall(r'^\| (\d+) \|(.*)$', texto, re.M)}
        for esperado in medicion.ESPERADOS:
            self.assertIn('`%s`' % esperado.codigo, filas[esperado.fila], esperado)

    def test_2_cada_codigo_es_del_catalogo(self):
        catalogo = set(re.findall(r'^\| \d{2} \| `([a-z0-9_]+)`',
                                  (RAIZ / 'docs' / 'codigos_reglas.md').read_text(encoding='utf-8'), re.M))
        self.assertLessEqual({e.codigo for e in medicion.ESPERADOS}, catalogo)


if __name__ == '__main__':
    unittest.main()

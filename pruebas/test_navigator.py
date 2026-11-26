"""La capa de ATT&CK Navigator de LowTide sale de las migraciones (#58, RC-106). Sin base ni red.

    python -m unittest -v pruebas/test_navigator.py

Si una migración agrega o corrige un mapeo, esta prueba falla hasta que se regenera la capa:
    python -m cirdan.navigator --escribir
"""
import json
import re
import unittest
from pathlib import Path

from cirdan import navigator

RAIZ = Path(__file__).resolve().parents[1]
CODIGOS = RAIZ / 'docs' / 'codigos_reglas.md'


class CapaNavigator(unittest.TestCase):

    def test_1_el_archivo_guardado_es_el_que_sale_de_las_migraciones(self):
        guardado = navigator.CAPA.read_text(encoding='utf-8')
        self.assertEqual(guardado, navigator.texto(),
                         'la capa no coincide con las migraciones: corre python -m cirdan.navigator --escribir')

    def test_2_cada_regla_del_catalogo_tiene_su_mapeo(self):
        """Las 40 reglas de docs/codigos_reglas.md, con técnica o sin ella: ninguna se queda fuera de la capa."""
        catalogo = set(re.findall(r'^\| \d{2} \| `([a-z0-9_]+)`', CODIGOS.read_text(encoding='utf-8'), re.M))
        self.assertGreaterEqual(len(catalogo), 40)
        self.assertEqual(set(navigator.mapeo()), catalogo)

    def test_3_gana_la_correccion_de_la_012(self):
        """La 011 puso T1552.001 a secret_in_public_repo y la 012 la cambió por T1593.003: vale la de la 012."""
        mapeo = navigator.mapeo()
        self.assertEqual(mapeo['secret_in_public_repo'][0], 'T1593.003')
        self.assertEqual(mapeo['breach_exposure'][0], 'T1589.001')
        self.assertIsNone(mapeo['cert_expired'])   # una debilidad de configuración no es una técnica

    def test_4_la_capa_es_valida_para_navigator(self):
        capa = json.loads(navigator.texto())
        self.assertEqual((capa['domain'], capa['versions']['attack'], capa['versions']['layer']),
                         ('enterprise-attack', '19', '4.5'))
        tecnicas = capa['techniques']
        self.assertTrue(tecnicas)
        ids = [t['techniqueID'] for t in tecnicas]
        self.assertEqual(len(ids), len(set(ids)))
        mapeo = navigator.mapeo()
        for tecnica in tecnicas:
            self.assertRegex(tecnica['techniqueID'], r'^T\d{4}(\.\d{3})?$')
            reglas = tecnica['comment'].removeprefix('Reglas de LowTide: ').split(', ')
            self.assertEqual(tecnica['score'], len(reglas))
            for regla in reglas:
                self.assertEqual(mapeo[regla][0], tecnica['techniqueID'], regla)
        self.assertEqual(capa['gradient']['maxValue'], max(t['score'] for t in tecnicas))
        self.assertNotIn('Cirdan', json.dumps(capa, ensure_ascii=False))   # el texto que se entrega dice LowTide

    def test_5_un_comentario_con_apostrofo_o_punto_y_coma_no_rompe_la_lectura(self):
        sentencias = navigator._sentencias("-- no es 'texto; ni corte\nUPDATE x SET a = 'uno; dos';\nSELECT 1;")
        self.assertEqual([s.strip() for s in sentencias if s.strip()], ["UPDATE x SET a = 'uno; dos'", 'SELECT 1'])


if __name__ == '__main__':
    unittest.main()

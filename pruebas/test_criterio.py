"""Pruebas del criterio de criticidad (#29), sin base de datos.

    python -m unittest -v pruebas/test_criterio.py
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_criterio.py
from score import criterio as c  # noqa: E402

PESOS_V1 = {'infrastructure': 0.30, 'digital_identity': 0.20, 'configuration': 0.20, 'data_leaks': 0.30}  # 02_datos_demo.sql


def notas(infra, identidad, config, fugas):
    return {'infrastructure': infra, 'digital_identity': identidad, 'configuration': config, 'data_leaks': fugas}


class Bandas(unittest.TestCase):

    def test_1_limites(self):
        casos = {0: 'low', 39: 'low', 40: 'medium', 59: 'medium', 60: 'high', 79: 'high', 80: 'critical', 100: 'critical'}
        for score, esperado in casos.items():
            self.assertEqual(c.banda(score), esperado, score)

    def test_2_ejemplo_del_reto_68_es_riesgo_alto(self):
        self.assertEqual((c.banda(68), c.nombre_banda(68)), ('high', 'alto'))

    def test_3_fuera_de_rango(self):
        for malo in (-1, 101):
            with self.assertRaises(ValueError):
                c.banda(malo)


class Piso(unittest.TestCase):

    def test_1_que_cuenta(self):
        self.assertTrue(c.cuenta_para_piso('critical', 'open'))
        self.assertTrue(c.cuenta_para_piso('critical', 'accepted_risk'))  # sigue en el score (#80)
        for severidad, estado in (('critical', 'resolved'), ('critical', 'false_positive'), ('high', 'open')):
            self.assertFalse(c.cuenta_para_piso(severidad, estado))

    def test_2_valores(self):
        self.assertEqual([c.piso(n) for n in (0, 1, 2, 5)], [0, 60, 80, 80])

    def test_3_demo_acme_demo_mx_queda_en_68(self):
        # 80, 55, 30 y 90 con los pesos v1 dan 68, y su fuga crítica abierta pone el piso en 60
        r = c.score_dominio(notas(80, 55, 30, 90), PESOS_V1, criticos=1)
        self.assertEqual(r, {'ponderado': 68, 'piso': 60, 'score': 68, 'banda': 'high', 'piso_aplicado': False})

    def test_4_el_promedio_no_esconde_un_critico(self):
        # como acme-portal.mx con una fuga crítica abierta: la nota de fugas sube a 70 y el ponderado a 43
        r = c.score_dominio(notas(40, 30, 20, 70), PESOS_V1, criticos=1)
        self.assertEqual((r['ponderado'], r['score'], r['banda'], r['piso_aplicado']), (43, 60, 'high', True))
        r = c.score_dominio(notas(40, 30, 20, 70), PESOS_V1, criticos=2)
        self.assertEqual((r['score'], r['banda']), (80, 'critical'))

    def test_5_sin_criticos_solo_cuenta_el_ponderado(self):
        r = c.score_dominio(notas(60, 50, 40, 60), PESOS_V1)  # acme-tienda.mx
        self.assertEqual((r['score'], r['banda'], r['piso_aplicado']), (54, 'medium', False))


class Ponderado(unittest.TestCase):

    def test_1_redondeo_hacia_arriba_en_punto_cinco(self):
        pesos = {'infrastructure': 0.5, 'digital_identity': 0.5, 'configuration': 0.0, 'data_leaks': 0.0}
        self.assertEqual(c.score_dominio(notas(60, 61, 0, 0), pesos)['ponderado'], 61)  # 60.5

    def test_2_pesos_que_no_suman_1(self):
        with self.assertRaises(ValueError):
            c.score_dominio(notas(1, 1, 1, 1), dict(PESOS_V1, data_leaks=0.4))

    def test_3_categorias_incompletas_o_fuera_de_rango(self):
        with self.assertRaises(ValueError):
            c.score_dominio({'infrastructure': 50}, PESOS_V1)
        with self.assertRaises(ValueError):
            c.score_dominio(notas(120, 0, 0, 0), PESOS_V1)


class Alerta(unittest.TestCase):

    def test_1_llega_o_pasa_el_umbral(self):
        self.assertTrue(c.dispara_alerta(60))
        self.assertTrue(c.dispara_alerta(68))
        self.assertFalse(c.dispara_alerta(59))

    def test_2_umbral_de_la_empresa(self):
        self.assertFalse(c.dispara_alerta(68, umbral=70))
        self.assertTrue(c.dispara_alerta(70, umbral=70))


if __name__ == '__main__':
    unittest.main(verbosity=2)

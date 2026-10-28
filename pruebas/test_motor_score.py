"""Pruebas unitarias del cálculo de score (#31), sin base de datos."""
import unittest

from cirdan.score import motor

PESOS_CATEGORIA = {
    'infrastructure': 0.30,
    'digital_identity': 0.20,
    'configuration': 0.20,
    'data_leaks': 0.30,
}


class MotorScore(unittest.TestCase):

    def test_aplica_peso_severidad_y_tope_de_regla(self):
        resultado = motor.calcular(
            [{'id': 'f1', 'rule_code': 'secret', 'severity': 'critical', 'status': 'open'}],
            {'secret': {'id': 'r1', 'category': 'data_leaks', 'weight': 0.5, 'max_penalty': 40}},
            PESOS_CATEGORIA,
        )
        self.assertEqual(resultado['category_scores']['data_leaks'], 40)
        self.assertEqual(resultado['contributions'][0]['penalty'], 40)
        self.assertEqual(resultado['contributions'][0]['factors']['uncapped_penalty'], 50)
        factores = resultado['contributions'][0]['factors']['rules']
        self.assertIn('Severidad 100 x peso 0.5 (tope 40)', factores[0]['label'])
        self.assertEqual(sum(f['points'] for f in factores), float(resultado['contributions'][0]['penalty']))

    def test_ignora_hallazgos_cerrados_y_aplica_piso_critico(self):
        hallazgos = [
            {'id': 'f1', 'rule_code': 'secret', 'severity': 'critical', 'status': 'open'},
            {'id': 'f2', 'rule_code': 'secret', 'severity': 'critical', 'status': 'accepted_risk'},
            {'id': 'f3', 'rule_code': 'secret', 'severity': 'critical', 'status': 'resolved'},
            {'id': 'f4', 'rule_code': 'secret', 'severity': 'critical', 'status': 'false_positive'},
        ]
        resultado = motor.calcular(
            hallazgos,
            {'secret': {'id': 'r1', 'category': 'data_leaks', 'weight': 0.5, 'max_penalty': 40}},
            PESOS_CATEGORIA,
        )
        self.assertEqual(resultado['critical_open'], 2)
        self.assertEqual(resultado['category_scores']['data_leaks'], 80)
        self.assertEqual(resultado['score'], 80)
        self.assertEqual(len(resultado['contributions']), 2)
        self.assertEqual(resultado['floor_message'], 'Subido a 80 por 2 hallazgos críticos vigentes; la suma ponderada da 24.')

    def test_las_notas_de_categoria_no_superan_cien(self):
        hallazgos = [
            {'id': 'f1', 'rule_code': 'secret', 'severity': 'high', 'status': 'open'},
            {'id': 'f2', 'rule_code': 'secret', 'severity': 'high', 'status': 'open'},
            {'id': 'f3', 'rule_code': 'secret', 'severity': 'high', 'status': 'open'},
        ]
        resultado = motor.calcular(
            hallazgos,
            {'secret': {'id': 'r1', 'category': 'data_leaks', 'weight': 0.5, 'max_penalty': 40}},
            PESOS_CATEGORIA,
        )
        self.assertEqual(resultado['category_scores']['data_leaks'], 100)
        self.assertIsNone(resultado['floor_message'])

    def test_falla_cerrada_si_falta_regla(self):
        with self.assertRaisesRegex(ValueError, 'sin regla activa'):
            motor.calcular(
                [{'id': 'f1', 'rule_code': 'unknown', 'severity': 'low', 'status': 'open'}],
                {}, PESOS_CATEGORIA,
            )

    def test_mensaje_piso_acepta_conteo_externo_del_historico(self):
        calc = {'piso_aplicado': True, 'score': 80, 'ponderado': 43}
        self.assertEqual(
            motor.mensaje_piso(calc, 2),
            'Subido a 80 por 2 hallazgos críticos vigentes; la suma ponderada da 43.',
        )


if __name__ == '__main__':
    unittest.main(verbosity=2)
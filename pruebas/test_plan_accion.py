"""Pruebas offline del plan de acción y el simulador (#42, #70)."""
import json
import unittest

from cirdan.score import plan

PESOS = {
    'infrastructure': 0.30,
    'digital_identity': 0.20,
    'configuration': 0.20,
    'data_leaks': 0.30,
}
REGLAS = {
    'secret': {'id': 'r1', 'category': 'data_leaks', 'weight': 0.5, 'max_penalty': 40, 'recommendation': 'Revoca la credencial.'},
    'spf_missing': {'id': 'r2', 'category': 'configuration', 'weight': 0.25, 'max_penalty': 8, 'recommendation': '=HYPERLINK("x")'},
}
HALLAZGOS = [
    {'id': 'f1', 'rule_code': 'secret', 'severity': 'critical', 'status': 'open'},
    {'id': 'f2', 'rule_code': 'spf_missing', 'severity': 'low', 'status': 'open'},
    {'id': 'f3', 'rule_code': 'secret', 'severity': 'critical', 'status': 'accepted_risk'},
]


class PlanAccion(unittest.TestCase):

    def test_plan_agrupa_hallazgos_por_regla_y_ordena_por_reduccion(self):
        resultado = plan.construir_plan('olmardo.com', HALLAZGOS, REGLAS, PESOS, partial_coverage=True)
        self.assertEqual(resultado['score_before'], 80)
        self.assertTrue(resultado['partial_coverage'])
        self.assertEqual([accion['id'] for accion in resultado['actions']], ['secret', 'spf_missing'])
        self.assertEqual(resultado['actions'][0]['finding_ids'], ['f1'])
        self.assertEqual(resultado['actions'][0]['finding_count'], 1)
        self.assertGreater(resultado['actions'][0]['score_reduction'], resultado['actions'][1]['score_reduction'])
        self.assertEqual(resultado['total'], 2)

    def test_simulacion_combinada_no_persiste_y_cuenta_riesgo_aceptado(self):
        resultado = plan.simular(HALLAZGOS, REGLAS, PESOS, ['secret', 'spf_missing'])
        self.assertEqual(resultado['score_before'], 80)
        self.assertEqual(resultado['score_after'], 60)
        self.assertEqual(resultado['method'], 'rules')
        self.assertEqual(resultado['category_scores_after']['configuration'], 0)

    def test_simulacion_rechaza_acciones_desconocidas_o_cerradas(self):
        with self.assertRaisesRegex(ValueError, 'desconocida'):
            plan.simular(HALLAZGOS, REGLAS, PESOS, ['unknown'])
        only_accepted = [dict(HALLAZGOS[2])]
        with self.assertRaisesRegex(ValueError, 'desconocida'):
            plan.simular(only_accepted, REGLAS, PESOS, ['secret'])
        with self.assertRaisesRegex(ValueError, 'al menos una'):
            plan.simular(HALLAZGOS, REGLAS, PESOS, [])

    def test_simulacion_ml_conserva_severidades_del_score_actual(self):
        hallazgos = [{'id': 'f1', 'rule_code': 'secret', 'severity': 'low', 'status': 'open'}]
        resultado = plan.simular(hallazgos, REGLAS, PESOS, ['secret'], {'f1': 'critical'})
        self.assertEqual(resultado['method'], 'ml')
        self.assertEqual(resultado['score_before'], 60)
        self.assertEqual(resultado['score_after'], 0)

    def test_exportaciones_escapan_celdas_con_formula(self):
        data = plan.construir_plan('olmardo.com', HALLAZGOS, REGLAS, PESOS)
        csv = plan.exportar_csv(data)
        self.assertTrue(csv.startswith('\ufeff'))
        self.assertIn("'=HYPERLINK", csv)
        json_exportado = json.loads(plan.exportar_json(data))
        accion = next(item for item in json_exportado['actions'] if item['id'] == 'spf_missing')
        self.assertTrue(accion['recommendation'].startswith("'="))


if __name__ == '__main__':
    unittest.main(verbosity=2)

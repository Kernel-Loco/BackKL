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

    def test_plan_y_simulacion_toman_el_score_guardado_como_actual(self):
        guardado = {'score': 85, 'category_scores': {'infrastructure': 80, 'digital_identity': 55,
                                                     'configuration': 30, 'data_leaks': 90}}
        resultado = plan.construir_plan('acme-demo.mx', HALLAZGOS, REGLAS, PESOS, guardado=guardado)
        self.assertEqual((resultado['score_before'], resultado['band_before']), (85, 'critical'))
        self.assertEqual(resultado['category_scores_before'], guardado['category_scores'])
        self.assertEqual([(a['id'], a['score_after'], a['score_reduction']) for a in resultado['actions']],
                         [('secret', 60, 20), ('spf_missing', 80, 0)])

        simulado = plan.simular(HALLAZGOS, REGLAS, PESOS, ['secret', 'spf_missing'], guardado=guardado)
        self.assertEqual((simulado['score_before'], simulado['band_before']), (85, 'critical'))
        self.assertEqual(simulado['category_scores_before'], guardado['category_scores'])
        self.assertEqual((simulado['score_after'], simulado['score_reduction']), (60, 20))

    def test_reduccion_nunca_negativa_con_un_score_guardado_viejo(self):
        # Un escaneo grabó hallazgos críticos y todavía no guarda su score: el motor ya da 80 y lo guardado es 28.
        guardado = {'score': 28, 'category_scores': {'infrastructure': 0, 'digital_identity': 0,
                                                     'configuration': 6.25, 'data_leaks': 0}}
        resultado = plan.construir_plan('acme-demo.mx', HALLAZGOS, REGLAS, PESOS, guardado=guardado)
        self.assertEqual(resultado['score_before'], 28)
        self.assertEqual([(a['id'], a['score_after'], a['score_reduction']) for a in resultado['actions']],
                         [('secret', 60, 20), ('spf_missing', 80, 0)])

    def test_plan_sin_hallazgos_abiertos_conserva_el_score_guardado(self):
        guardado = {'score': 54, 'category_scores': {'infrastructure': 60, 'digital_identity': 50,
                                                     'configuration': 40, 'data_leaks': 60}}
        resultado = plan.construir_plan('acme-tienda.mx', [], REGLAS, PESOS, guardado=guardado)
        self.assertEqual((resultado['score_before'], resultado['band_before']), (54, 'medium'))
        self.assertEqual((resultado['actions'], resultado['total']), ([], 0))

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

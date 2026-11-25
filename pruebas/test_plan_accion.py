"""Pruebas offline del plan de acción y el simulador (#42, #70), por activo y en orden acumulado (RC-263)."""
import csv
import io
import itertools
import json
import unittest

from cirdan.score import motor, plan

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

    def test_simulacion_coincide_con_recalculo_del_motor_tras_resolver_acciones(self):
        casos = (['secret'], ['secret', 'spf_missing'])
        calculo_antes = motor.calcular(HALLAZGOS, REGLAS, PESOS)

        for action_ids in casos:
            with self.subTest(action_ids=action_ids):
                resueltos = [
                    {**hallazgo, 'status': 'resolved'}
                    if hallazgo['status'] == 'open' and hallazgo['rule_code'] in action_ids
                    else dict(hallazgo)
                    for hallazgo in HALLAZGOS
                ]
                calculo_despues = motor.calcular(resueltos, REGLAS, PESOS)
                simulado = plan.simular(HALLAZGOS, REGLAS, PESOS, action_ids)

                self.assertEqual(simulado['score_before'], calculo_antes['score'])
                self.assertEqual(simulado['category_scores_before'], calculo_antes['category_scores'])
                self.assertEqual(simulado['score_after'], calculo_despues['score'])
                self.assertEqual(simulado['category_scores_after'], calculo_despues['category_scores'])
                self.assertEqual(simulado['score_reduction'],
                                 calculo_antes['score'] - calculo_despues['score'])
                self.assertEqual([hallazgo['status'] for hallazgo in HALLAZGOS],
                                 ['open', 'open', 'accepted_risk'])

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

    def test_bandas_del_plan_y_la_simulacion_usan_los_cortes_del_juego(self):
        # RC-237: con 50, 70 y 85 el 80 de antes es alto y no crítico, y el 60 del después es medio.
        cortes = {'medium': 50, 'high': 70, 'critical': 85}
        resultado = plan.construir_plan('olmardo.com', HALLAZGOS, REGLAS, PESOS, cortes=cortes)
        self.assertEqual((resultado['score_before'], resultado['band_before']), (85, 'critical'))
        simulado = plan.simular(HALLAZGOS, REGLAS, PESOS, ['secret'], cortes=cortes)
        self.assertEqual(simulado['band_before'], 'critical')
        self.assertEqual(simulado['band_after'], plan.criterio.banda(simulado['score_after'], cortes))
        guardado = {'score': 80, 'category_scores': {'infrastructure': 80, 'digital_identity': 55,
                                                     'configuration': 30, 'data_leaks': 90}}
        con_guardado = plan.simular(HALLAZGOS, REGLAS, PESOS, ['secret', 'spf_missing'], guardado=guardado,
                                    cortes=cortes)
        self.assertEqual((con_guardado['score_before'], con_guardado['band_before']), (80, 'high'))
        sin_cortes = plan.simular(HALLAZGOS, REGLAS, PESOS, ['secret', 'spf_missing'], guardado=guardado)
        self.assertEqual(sin_cortes['band_before'], 'critical')

    def test_exportaciones_escapan_celdas_con_formula(self):
        data = plan.construir_plan('olmardo.com', HALLAZGOS, REGLAS, PESOS)
        csv = plan.exportar_csv(data)
        self.assertTrue(csv.startswith('\ufeff'))
        self.assertIn("'=HYPERLINK", csv)
        json_exportado = json.loads(plan.exportar_json(data))
        accion = next(item for item in json_exportado['actions'] if item['id'] == 'spf_missing')
        self.assertTrue(accion['recommendation'].startswith("'="))


# RC-263: un riesgo aceptado crítico deja el piso de 60 que el plan no puede quitar, y www tiene dos reglas que
# juntas pasan el tope de 100 de infraestructura.
REGLAS_TOPE = {
    'secret': {'id': 'r1', 'category': 'data_leaks', 'weight': 1, 'max_penalty': 100, 'recommendation': 'Revoca.'},
    'old_tls': {'id': 'r3', 'category': 'infrastructure', 'weight': 1, 'max_penalty': 100,
                'recommendation': '=HYPERLINK("tls")'},
    'open_port': {'id': 'r4', 'category': 'infrastructure', 'weight': 1, 'max_penalty': 100,
                  'recommendation': 'Cierra el puerto.'},
    'spf_missing': {'id': 'r2', 'category': 'configuration', 'weight': 1, 'max_penalty': 100,
                    'recommendation': 'Publica SPF.'},
}
DOM = {'asset_id': 'a-dom', 'asset_type': 'domain', 'asset_value': 'acme-demo.mx'}
WWW = {'asset_id': 'a-www', 'asset_type': 'subdomain', 'asset_value': '=www.acme-demo.mx'}
HALLAZGOS_TOPE = [
    {'id': 'f1', 'rule_code': 'secret', 'severity': 'critical', 'status': 'accepted_risk', **DOM},
    {'id': 'f2', 'rule_code': 'old_tls', 'severity': 'high', 'status': 'open', **WWW},
    {'id': 'f3', 'rule_code': 'open_port', 'severity': 'medium', 'status': 'open', **WWW},
    {'id': 'f4', 'rule_code': 'spf_missing', 'severity': 'high', 'status': 'open', **DOM},
]
CAMPOS_DE_HOY = ('id', 'rule_code', 'category', 'recommendation', 'finding_ids', 'finding_count', 'score_after',
                 'score_reduction')


def resolver(hallazgos, finding_ids):
    return [{**h, 'status': 'resolved'} if h['id'] in finding_ids else dict(h) for h in hallazgos]


class PlanAcumulado(unittest.TestCase):
    """RC-263: plan por activo y en orden acumulado."""

    def test_suma_de_reducciones_sueltas_pasa_de_la_acumulada_por_un_tope(self):
        data = plan.construir_plan('acme-demo.mx', HALLAZGOS_TOPE, REGLAS_TOPE, PESOS)
        self.assertEqual(data['score_before'], 75)
        self.assertEqual([(a['id'], a['score_reduction'], a['score_reduction_acumulado'], a['score_after_acumulado'])
                          for a in data['actions']],
                         [('spf_missing', 15, 15, 60), ('old_tls', 15, 0, 60), ('open_port', 7, 0, 60)])
        sueltas = sum(a['score_reduction'] for a in data['actions'])
        acumulada = sum(a['score_reduction_acumulado'] for a in data['actions'])
        self.assertEqual((sueltas, acumulada), (37, 15))
        self.assertGreater(sueltas, acumulada)

    def test_la_ultima_acumulada_deja_el_score_de_resolver_todo(self):
        casos = (('reglas', HALLAZGOS_TOPE, REGLAS_TOPE, None, None), ('reglas', HALLAZGOS, REGLAS, None, None),
                 ('ml', HALLAZGOS_TOPE, REGLAS_TOPE, {'f2': 'low', 'f4': 'critical'}, None),
                 ('cortes', HALLAZGOS_TOPE, REGLAS_TOPE, None, {'medium': 50, 'high': 70, 'critical': 85}))
        for nombre, hallazgos, reglas, severidades, cortes in casos:
            for agrupar in plan.AGRUPACIONES:
                if agrupar == 'activo' and hallazgos is HALLAZGOS:
                    continue   # HALLAZGOS no trae activo
                with self.subTest(caso=nombre, agrupar=agrupar):
                    data = plan.construir_plan('acme-demo.mx', hallazgos, reglas, PESOS, severidades=severidades,
                                               cortes=cortes, agrupar=agrupar)
                    abiertos = {h['id'] for h in hallazgos if h['status'] == 'open'}
                    preparados = plan._hallazgos_con_severidad(hallazgos, severidades)
                    todo = motor.calcular(resolver(preparados, abiertos), reglas, PESOS, cortes)['score']
                    vigente = motor.calcular(preparados, reglas, PESOS, cortes)['score']
                    self.assertEqual(data['actions'][-1]['score_after_acumulado'], todo)
                    self.assertEqual(sum(a['score_reduction_acumulado'] for a in data['actions']), vigente - todo)
                    # Cada acumulado es lo que baja el motor al resolverla después de todas las de arriba.
                    resueltos, antes = set(), vigente
                    for accion in data['actions']:
                        resueltos |= set(accion['finding_ids'])
                        despues = motor.calcular(resolver(preparados, resueltos), reglas, PESOS, cortes)['score']
                        self.assertEqual((accion['score_after_acumulado'], accion['score_reduction_acumulado']),
                                         (despues, antes - despues), accion['id'])
                        self.assertGreaterEqual(accion['score_reduction_acumulado'], 0)
                        antes = despues

    def test_orden_voraz_y_empate_por_categoria_e_id(self):
        # Con el piso: solas, spf_missing y old_tls bajan 15 cada una y gana la de configuración (el desempate de
        # hoy). Después nadie baja nada y el empate sigue categoría e id (prueba anterior).
        # Sin el piso: old_tls sola baja 15, spf_missing 10 y open_port 7 (la categoría sigue topada). Después de
        # old_tls, open_port baja 15 y spf_missing 10, así que open_port sube al segundo lugar.
        sin_piso = [h for h in HALLAZGOS_TOPE if h['id'] != 'f1']
        sin_piso = [dict(h, severity='medium') if h['id'] == 'f4' else h for h in sin_piso]
        data = plan.construir_plan('acme-demo.mx', sin_piso, REGLAS_TOPE, PESOS)
        self.assertEqual(data['score_before'], 40)
        self.assertEqual([(a['id'], a['score_reduction'], a['score_reduction_acumulado']) for a in data['actions']],
                         [('old_tls', 15, 15), ('open_port', 7, 15), ('spf_missing', 10, 10)])

    def test_por_activo_junta_dos_reglas_del_mismo_host(self):
        data = plan.construir_plan('acme-demo.mx', HALLAZGOS_TOPE, REGLAS_TOPE, PESOS, agrupar='activo')
        self.assertEqual(data['grouping'], 'activo')
        www = next(a for a in data['actions'] if a['id'] == 'a-www')
        self.assertEqual((www['asset_value'], www['asset_type'], www['finding_ids'], www['finding_count']),
                         ('=www.acme-demo.mx', 'subdomain', ['f2', 'f3'], 2))
        self.assertEqual(www['rule_codes'], ['old_tls', 'open_port'])
        self.assertEqual([r['recommendation'] for r in www['recommendations']],
                         ['=HYPERLINK("tls")', 'Cierra el puerto.'])
        self.assertEqual(www['categories'], ['infrastructure'])
        # Solo resolver los dos hallazgos de www: infraestructura baja de 100 a 0 y el piso de 60 la frena en 60.
        self.assertEqual((www['score_after'], www['score_reduction']), (60, 15))
        dominio = next(a for a in data['actions'] if a['id'] == 'a-dom')
        self.assertEqual(dominio['finding_ids'], ['f4'])   # el riesgo aceptado no es una acción
        self.assertEqual([a['id'] for a in data['actions']], ['a-dom', 'a-www'])   # empate: configuración primero
        self.assertEqual([a['score_reduction_acumulado'] for a in data['actions']], [15, 0])

    def test_por_regla_conserva_lo_de_hoy_y_suma_la_acumulada(self):
        data = plan.construir_plan('acme-demo.mx', HALLAZGOS_TOPE, REGLAS_TOPE, PESOS)
        for accion in data['actions']:
            solo = plan.simular(HALLAZGOS_TOPE, REGLAS_TOPE, PESOS, [accion['id']])
            self.assertEqual((accion['score_after'], accion['score_reduction']),
                             (solo['score_after'], solo['score_reduction']))
            self.assertEqual(set(accion) - set(CAMPOS_DE_HOY), {'score_reduction_acumulado', 'score_after_acumulado'})
        self.assertEqual(data['grouping'], 'regla')
        with self.assertRaisesRegex(ValueError, 'agrupar'):
            plan.construir_plan('acme-demo.mx', HALLAZGOS_TOPE, REGLAS_TOPE, PESOS, agrupar='host')
        with self.assertRaisesRegex(ValueError, 'sin activo'):
            plan.construir_plan('acme-demo.mx', HALLAZGOS, REGLAS, PESOS, agrupar='activo')

    def test_exportaciones_suman_la_acumulada_y_escapan_formulas(self):
        por_regla = plan.construir_plan('acme-demo.mx', HALLAZGOS_TOPE, REGLAS_TOPE, PESOS)
        filas = list(csv.reader(io.StringIO(plan.exportar_csv(por_regla).lstrip('﻿'))))
        self.assertEqual(filas[0], ['dominio', 'accion', 'categoria', 'recomendacion', 'hallazgos', 'ids_hallazgo',
                                    'score_antes', 'score_despues', 'reduccion_score', 'reduccion_acumulada',
                                    'score_despues_acumulado'])
        self.assertEqual([f[1] for f in filas[1:]], ['spf_missing', 'old_tls', 'open_port'])
        self.assertEqual([f[9:] for f in filas[1:]], [['15', '60'], ['0', '60'], ['0', '60']])
        self.assertEqual(filas[2][3], '\'=HYPERLINK("tls")')

        por_activo = plan.construir_plan('acme-demo.mx', HALLAZGOS_TOPE, REGLAS_TOPE, PESOS, agrupar='activo')
        filas = list(csv.reader(io.StringIO(plan.exportar_csv(por_activo).lstrip('﻿'))))
        self.assertEqual(filas[0][-5:], ['reduccion_acumulada', 'score_despues_acumulado', 'activo', 'tipo_activo',
                                         'reglas'])
        www = filas[2]
        self.assertEqual(www[1], 'a-www')
        self.assertEqual((www[3], www[11], www[12], www[13]),
                         ('\'=HYPERLINK("tls") | Cierra el puerto.', "'=www.acme-demo.mx", 'subdomain',
                          'old_tls;open_port'))
        exportado = json.loads(plan.exportar_json(por_activo))
        www = next(a for a in exportado['actions'] if a['id'] == 'a-www')
        self.assertEqual((www['asset_value'], www['score_reduction_acumulado']), ("'=www.acme-demo.mx", 0))
        self.assertTrue(www['recommendations'][0]['recommendation'].startswith("'="))

    def test_el_calculo_rapido_coincide_con_el_motor(self):
        # El orden voraz no llama al motor por cada candidato: _Puntaje tiene que dar lo mismo en todo subconjunto.
        severidades = {'f2': 'critical', 'f3': 'critical'}
        for sev, cortes in ((None, None), (severidades, {'medium': 50, 'high': 70, 'critical': 85})):
            preparados = plan._hallazgos_con_severidad(HALLAZGOS_TOPE, sev)
            puntaje = plan._Puntaje(preparados, REGLAS_TOPE, PESOS, cortes)
            ids = [h['id'] for h in preparados]
            for n in range(len(ids) + 1):
                for subconjunto in itertools.combinations(ids, n):
                    with self.subTest(sev=bool(sev), resueltos=subconjunto):
                        esperado = motor.calcular(resolver(preparados, set(subconjunto)), REGLAS_TOPE, PESOS,
                                                  cortes)['score']
                        self.assertEqual(puntaje.sin(subconjunto), esperado)


if __name__ == '__main__':
    unittest.main(verbosity=2)

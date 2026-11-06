"""Pruebas offline de validación y resolución de pesos (#32)."""
import unittest

from cirdan.score import configuracion, criterio


class Pesos(unittest.TestCase):

    def test_acepta_las_cuatro_categorias_que_suman_uno(self):
        pesos = {'infrastructure': .3, 'digital_identity': .2, 'configuration': .2, 'data_leaks': .3}
        self.assertEqual(configuracion.validar_pesos(pesos), pesos)

    def test_rechaza_categorias_faltantes_o_extra(self):
        base = {categoria: .25 for categoria in criterio.CATEGORIAS}
        for pesos in (dict(list(base.items())[:-1]), {**base, 'other': 0}):
            with self.subTest(pesos=pesos), self.assertRaisesRegex(ValueError, 'categorías'):
                configuracion.validar_pesos(pesos)

    def test_rechaza_suma_distinta_de_uno(self):
        pesos = {'infrastructure': .3, 'digital_identity': .2, 'configuration': .2, 'data_leaks': .2}
        with self.assertRaisesRegex(ValueError, 'sumar 1'):
            configuracion.validar_pesos(pesos)

    def test_rechaza_pesos_no_finitos_negativos_mayores_a_uno_y_booleanos(self):
        casos = (float('nan'), -0.1, 1.1, True)
        for valor in casos:
            pesos = {categoria: .25 for categoria in criterio.CATEGORIAS}
            pesos['infrastructure'] = valor
            with self.subTest(valor=valor), self.assertRaisesRegex(ValueError, '0 y 1'):
                configuracion.validar_pesos(pesos)


class ConexionSimulada:

    def __init__(self):
        self.sql = None
        self.parametros = None

    def execute(self, sql, parametros):
        self.sql = sql
        self.parametros = parametros
        return ResultadoSimulado(fila='resultado')


class ResultadoSimulado:

    def __init__(self, fila=None, filas=None):
        self.fila = fila
        self.filas = filas or []

    def fetchone(self):
        return self.fila

    def fetchall(self):
        return self.filas


class JuegoActivo(unittest.TestCase):

    def test_busca_set_del_tenant_con_fallback_global(self):
        conn = ConexionSimulada()
        self.assertEqual(configuracion.juego_activo(conn, 'org-1'), 'resultado')
        self.assertIn('activated_at', conn.sql)
        self.assertIn('organization_id = %s OR organization_id IS NULL', conn.sql)
        self.assertIn('ORDER BY CASE WHEN organization_id = %s THEN 0 ELSE 1 END', conn.sql)
        self.assertEqual(conn.parametros, ('org-1', 'org-1'))


class Recalculo:

    def __init__(self):
        self.consultas = []
        self.aportes = []

    def execute(self, sql, parametros=()):
        self.consultas.append((sql, parametros))
        if sql.startswith('SELECT DISTINCT ON (domain_id)'):
            return ResultadoSimulado(filas=[{
                'domain_id': 'domain-1', 'scan_id': 'scan-1', 'score_id': 'score-anterior',
                'partial_coverage': True, 'method': 'ml', 'model_version': 'v-test',
                'model_fallback_reason': None,
            }])
        if sql.startswith('SELECT id::text, code, category'):
            return ResultadoSimulado(filas=[{
                'id': 'rule-v2', 'code': 'spf_missing', 'category': 'configuration',
                'weight': 1, 'max_penalty': 40,
            }])
        if sql.startswith('SELECT f.id::text AS id'):
            return ResultadoSimulado(filas=[{
                'id': 'finding-1', 'rule_code': 'spf_missing', 'severity': 'medium', 'status': 'open',
                'score_severity': 'high',
                'previous_factors': {'confidence': .91, 'shap': [{'feature': 'sensibilidad'}]},
            }])
        if sql.startswith('INSERT INTO domain_scores'):
            return ResultadoSimulado(fila={'id': 'score-nuevo'})
        if sql.startswith('INSERT INTO score_contributions'):
            self.aportes.append((sql, parametros))
        return ResultadoSimulado()


class RecalculoScores(unittest.TestCase):

    def test_inserta_snapshot_rules_change_sin_reescribir_historico(self):
        conn = Recalculo()
        pesos = {categoria: .25 for categoria in criterio.CATEGORIAS}
        recalculados = configuracion.recalcular_scores(conn, 'org-1', 'ruleset-v2', pesos)
        score_sql, score_params = next((sql, params) for sql, params in conn.consultas
                                      if sql.startswith('INSERT INTO domain_scores'))
        aporte = conn.aportes[0][1]
        factores = aporte[6].obj

        self.assertEqual(recalculados, 1)
        self.assertIn("'rules_change'", score_sql)
        self.assertEqual(score_params[1:4], ('domain-1', 'scan-1', 'ruleset-v2'))
        self.assertEqual(score_params[6:9], ('ml', 'v-test', None))
        self.assertTrue(score_params[9])
        self.assertEqual(aporte[5], 'high')
        self.assertEqual(factores['confidence'], .91)
        self.assertEqual(factores['shap'][0]['feature'], 'sensibilidad')
        self.assertFalse(any('UPDATE domain_scores' in sql for sql, _ in conn.consultas))


if __name__ == '__main__':
    unittest.main(verbosity=2)
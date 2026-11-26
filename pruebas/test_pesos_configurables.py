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


class CandadoDePesos(unittest.TestCase):

    def test_la_llave_pasa_por_uuid_como_la_de_los_hallazgos(self):
        """RC-62: el uuid en mayúsculas de la línea de comandos y el de la sesión caen en el mismo candado."""
        conn = ConexionSimulada()
        configuracion.bloquear_pesos(conn, '20000000-0000-4000-8000-00000000000A')
        self.assertIn('hashtextextended(%s::uuid::text, 32)', conn.sql)
        self.assertEqual(conn.parametros, ('20000000-0000-4000-8000-00000000000A',))


class Recalculo:

    def __init__(self, cortes=None, critico=False):
        self.consultas = []
        self.aportes = []
        self.cortes = cortes or {'band_medium_from': 40, 'band_high_from': 60, 'band_critical_from': 80}
        self.severidad, self.severidad_score = ('critical', 'critical') if critico else ('medium', 'high')

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
                'id': 'finding-1', 'rule_code': 'spf_missing', 'severity': self.severidad, 'status': 'open',
                'score_severity': self.severidad_score,
                'previous_factors': {'confidence': .91, 'shap': [{'feature': 'sensibilidad'}]},
            }])
        if sql.startswith('SELECT band_medium_from'):
            return ResultadoSimulado(fila=self.cortes)
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
        # El motivo va como parámetro desde RC-133 (el triage recalcula con 'correction'); por omisión, rules_change.
        self.assertEqual(score_params[6], 'rules_change')
        self.assertEqual(score_params[1:4], ('domain-1', 'scan-1', 'ruleset-v2'))
        self.assertEqual(score_params[7:10], ('ml', 'v-test', None))
        self.assertTrue(score_params[10])
        self.assertEqual(aporte[5], 'high')
        self.assertEqual(factores['confidence'], .91)
        self.assertEqual(factores['shap'][0]['feature'], 'sensibilidad')
        self.assertFalse(any('UPDATE domain_scores' in sql for sql, _ in conn.consultas))
        self.assertIn('clock_timestamp()', score_sql)  # el orden de computed_at es el del candado de pesos (RC-62)


    def test_el_triage_recalcula_un_solo_dominio_con_correction(self):
        # RC-133: un falso positivo o un hallazgo reabierto recalcula solo su dominio, con reason 'correction'.
        conn = Recalculo()
        pesos = {categoria: .25 for categoria in criterio.CATEGORIAS}
        configuracion.recalcular_scores(conn, 'org-1', 'ruleset-v2', pesos, dominio='domain-1', motivo='correction')
        anteriores = next(params for sql, params in conn.consultas if sql.startswith('SELECT DISTINCT ON'))
        self.assertEqual(anteriores, ('org-1', 'domain-1', 'domain-1'))
        score_params = next(params for sql, params in conn.consultas if sql.startswith('INSERT INTO domain_scores'))
        self.assertEqual(score_params[6], 'correction')

    def test_un_dominio_ml_sin_severidades_congeladas_falla_o_se_salta(self):
        # RC-310: sin lista de saltados lanza ValueError. Con ella, se salta y no inserta nada de ese dominio.
        pesos = {categoria: .25 for categoria in criterio.CATEGORIAS}
        conn = Recalculo()
        conn.severidad_score = None
        with self.assertRaisesRegex(ValueError, 'severidades ML congeladas'):
            configuracion.recalcular_scores(conn, 'org-1', 'ruleset-v2', pesos)
        conn = Recalculo()
        conn.severidad_score = None
        saltados = []
        self.assertEqual(configuracion.recalcular_scores(conn, 'org-1', 'ruleset-v2', pesos, saltados=saltados), 0)
        self.assertEqual(saltados, ['domain-1'])
        self.assertFalse(any(sql.startswith('INSERT') for sql, _ in conn.consultas))

    def _score_guardado(self, conn):
        return next(params for sql, params in conn.consultas if sql.startswith('INSERT INTO domain_scores'))[4]

    def test_usa_los_cortes_del_juego_nuevo_para_el_piso(self):
        # RC-237: con cortes 50, 70 y 85, un crítico deja el dominio en 70 y no en el 60 de la plantilla.
        pesos = {categoria: .25 for categoria in criterio.CATEGORIAS}
        conn = Recalculo({'band_medium_from': 50, 'band_high_from': 70, 'band_critical_from': 85}, critico=True)
        configuracion.recalcular_scores(conn, 'org-1', 'ruleset-v2', pesos)
        self.assertEqual(self._score_guardado(conn), 70)
        lectura = next(params for sql, params in conn.consultas if sql.startswith('SELECT band_medium_from'))
        self.assertEqual(lectura, ('ruleset-v2',))
        plantilla = Recalculo(critico=True)
        configuracion.recalcular_scores(plantilla, 'org-1', 'ruleset-v2', pesos)
        self.assertEqual(self._score_guardado(plantilla), 60)


class CortesDelJuego(unittest.TestCase):

    def test_lee_los_cortes_por_id_y_falla_si_no_existe(self):
        conn = Recalculo({'band_medium_from': 50, 'band_high_from': 70, 'band_critical_from': 85})
        self.assertEqual(configuracion.cortes_del_juego(conn, 'rs-1'), {'medium': 50, 'high': 70, 'critical': 85})

        class SinFila(Recalculo):
            def execute(self, sql, parametros=()):
                return ResultadoSimulado()
        with self.assertRaises(ValueError):
            configuracion.cortes_del_juego(SinFila(), 'rs-x')

    def test_cortes_de_fila(self):
        fila = {'band_medium_from': 45, 'band_high_from': 65, 'band_critical_from': 85, 'otro': 1}
        self.assertEqual(configuracion.cortes_de_fila(fila), {'medium': 45, 'high': 65, 'critical': 85})


if __name__ == '__main__':
    unittest.main(verbosity=2)
"""Pruebas offline del clasificador v1 y sus explicaciones SHAP (#34–#36)."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pandas as pd

from cirdan.ml import inferencia, modelo
from cirdan import orquestador
from psycopg.types.json import Jsonb


class ModeloMl(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.bundle = modelo.entrenar()

    def test_entrena_con_split_fijo_y_supera_ambas_lineas_base(self):
        metricas = self.bundle['metrics']
        self.assertEqual((metricas['filas_entrenamiento'], metricas['filas_prueba']), (287, 138))
        self.assertEqual(metricas['dataset'], 'datos/ml/rc65/dataset.csv')
        self.assertEqual(metricas['origen_etiquetas'], 'LLM; sin validación humana')
        self.assertEqual(metricas['particionamiento'], 'por_plantilla')
        self.assertGreater(metricas['modelo']['macro_f1'], metricas['lineas_base']['reglas_macro_f1'])
        self.assertGreater(metricas['modelo']['macro_f1'], metricas['lineas_base']['sensibilidad_macro_f1'])
        self.assertTrue(metricas['integrable'])
        self.assertEqual(set(metricas['modelo']['por_clase']), {'alta', 'media', 'baja'})
        self.assertEqual(len(metricas['modelo']['matriz_confusion']), 3)

    def test_entrenar_rechaza_plantilla_en_train_y_prueba(self):
        filas = [
            {'plantilla': 'plantilla-a', 'particion': particion, 'tipo': 'tipo-a', 'antiguedad_dias': 1,
             'exposicion': 'publica', 'sensibilidad': 'baja', 'etiqueta': 'baja', 'clase_reglas': 'baja'}
            for particion in ('entrenamiento', 'prueba')
        ]
        with tempfile.TemporaryDirectory() as directorio:
            ruta = Path(directorio) / 'dataset.csv'
            pd.DataFrame(filas).to_csv(ruta, index=False)
            with self.assertRaisesRegex(ValueError, 'plantilla'):
                modelo.entrenar(ruta)

    def test_entrenar_rechaza_etiqueta_fuera_de_las_tres_clases(self):
        filas = [
            {'plantilla': 'plantilla-' + particion, 'particion': particion, 'tipo': 'tipo-a',
             'antiguedad_dias': 1, 'exposicion': 'publica', 'sensibilidad': 'baja',
             'etiqueta': 'critica', 'clase_reglas': 'baja'}
            for particion in ('entrenamiento', 'prueba')
        ]
        with tempfile.TemporaryDirectory() as directorio:
            ruta = Path(directorio) / 'dataset.csv'
            pd.DataFrame(filas).to_csv(ruta, index=False)
            with self.assertRaisesRegex(ValueError, 'alta, baja y media'):
                modelo.entrenar(ruta)

    def test_artefacto_se_serializa_con_su_version_y_metricas(self):
        with tempfile.TemporaryDirectory() as directorio:
            artefacto = Path(directorio) / 'modelo.joblib'
            ficha = Path(directorio) / 'metricas.json'
            modelo.guardar(self.bundle, artefacto, ficha)
            cargado = modelo.joblib.load(artefacto)
            self.assertEqual(cargado['version'], modelo.VERSION)
            self.assertEqual(cargado['metrics'], self.bundle['metrics'])
            self.assertTrue(ficha.exists())

    def test_artefacto_de_produccion_carga_con_version_integrable(self):
        inferencia.cargar_modelo.cache_clear()
        bundle = inferencia.cargar_modelo()
        self.assertEqual(bundle['version'], modelo.VERSION)
        self.assertTrue(bundle['metrics']['integrable'])
        self.assertEqual(bundle['metrics']['particionamiento'], 'por_plantilla')

    def test_inferencia_da_severidad_confianza_y_top_tres_shap(self):
        fila = {
            'id': 'f-ml',
            'severity': 'high',
            'caracteristicas': {
                'tipo': 'software_desactualizado',
                'antiguedad_dias': 180,
                'exposicion': 'directa',
                'sensibilidad': 'alta',
            },
        }
        prediccion = inferencia.predecir(self.bundle, [fila])['f-ml']
        self.assertIn(prediccion['severity'], ('high', 'medium', 'low'))
        self.assertIn(prediccion['model_prediction'], ('high', 'medium', 'low'))
        self.assertGreaterEqual(prediccion['confidence'], 0)
        self.assertLessEqual(prediccion['confidence'], 1)
        self.assertEqual(len(prediccion['shap']), 3)
        self.assertTrue(all(item['feature'] in fila['caracteristicas'] for item in prediccion['shap']))

    def test_modelo_no_degrada_severidad_critica(self):
        fila = {
            'id': 'f-critical',
            'severity': 'critical',
            'caracteristicas': {
                'tipo': 'correos_en_brecha',
                'antiguedad_dias': 10,
                'exposicion': 'publica',
                'sensibilidad': 'alta',
            },
        }
        self.assertEqual(inferencia.predecir(self.bundle, [fila])['f-critical']['severity'], 'critical')

    def test_inferencia_reconstruye_caracteristicas_de_hallazgo_seed(self):
        fila = {
            'id': 'f-seed', 'severity': 'high', 'rule_code': 'breach_exposure', 'asset_type': 'domain',
            'evidence': {'data_classes': ['Passwords']},
        }
        prediccion = inferencia.predecir(self.bundle, [fila])['f-seed']
        self.assertIn(prediccion['severity'], ('high', 'medium', 'low'))
        self.assertEqual(len(prediccion['shap']), 3)


class ResultadoSimulado:

    def __init__(self, filas=(), fila=None):
        self.filas = filas
        self.fila = fila

    def fetchall(self):
        return self.filas

    def fetchone(self):
        return self.fila


class ConexionSimulada:

    def __init__(self):
        self.consultas = []

    def execute(self, sql, parametros=()):
        self.consultas.append((sql, parametros))
        if sql.startswith('SELECT f.id::text'):
            return ResultadoSimulado([{
                'id': 'finding-1', 'rule_code': 'spf_missing', 'base_severity': 'medium', 'severity': 'medium',
                'status': 'open', 'evidence': {}, 'asset_type': 'domain', 'asset_first_seen': None,
                'detected_at': None, 'scan_at': None,
                'caracteristicas': {'tipo': 'spf_faltante', 'antiguedad_dias': 0,
                                    'exposicion': 'publica', 'sensibilidad': 'media'},
            }])
        if 'RETURNING id::text' in sql:
            return ResultadoSimulado(fila={'id': 'score-1'})
        return ResultadoSimulado()


class IntegracionScoreMl(unittest.TestCase):

    REGLAS = {'spf_missing': {'id': 'rule-1', 'category': 'configuration', 'weight': 1, 'max_penalty': 40}}
    PESOS = {'infrastructure': .3, 'digital_identity': .2, 'configuration': .2, 'data_leaks': .3}

    def guardar(self, bundle, fallo=None):
        conexion = ConexionSimulada()
        with mock.patch.object(inferencia, 'cargar_modelo', side_effect=fallo) if fallo else \
                mock.patch.object(inferencia, 'cargar_modelo', return_value=bundle), \
                mock.patch.object(inferencia, 'predecir', return_value={
                    'finding-1': {'severity': 'high', 'model_prediction': 'high', 'confidence': .91,
                                  'shap': [{'feature': 'sensibilidad', 'value': 'media', 'contribution': .2}]},
                }) as predecir:
            orquestador._guardar_score(conexion, 'org', 'domain', 'scan', 'ruleset', self.REGLAS, self.PESOS, False)
        return conexion, predecir

    def test_persiste_version_confianza_y_shap_con_ml(self):
        conexion, _ = self.guardar({'version': 'v-test', 'metrics': {'integrable': True}})
        score = next(params for sql, params in conexion.consultas if 'INSERT INTO domain_scores' in sql)
        self.assertEqual(score[6:9], ('ml', 'v-test', None))
        aporte = next(params for sql, params in conexion.consultas if 'INSERT INTO score_contributions' in sql)
        factores = aporte[6].obj
        self.assertEqual(factores['model_prediction'], 'high')
        self.assertEqual(factores['confidence'], .91)
        self.assertEqual(factores['shap'][0]['feature'], 'sensibilidad')

    def test_modelo_no_integrable_usa_reglas_y_conserva_shap(self):
        conexion, predecir = self.guardar({'version': 'v-test', 'metrics': {'integrable': False}})
        score = next(params for sql, params in conexion.consultas if 'INSERT INTO domain_scores' in sql)
        self.assertEqual(score[6:9], ('rules', None, 'macro_f1_no_supera_reglas'))
        predecir.assert_called_once()
        aporte = next(params for sql, params in conexion.consultas if 'INSERT INTO score_contributions' in sql)
        self.assertEqual(aporte[5], 'medium')
        self.assertEqual(aporte[6].obj['model_prediction'], 'high')
        self.assertEqual(aporte[6].obj['shap'][0]['feature'], 'sensibilidad')

    def test_artefacto_ausente_usa_reglas_con_motivo(self):
        conexion, predecir = self.guardar(None, FileNotFoundError())
        score = next(params for sql, params in conexion.consultas if 'INSERT INTO domain_scores' in sql)
        self.assertEqual(score[6:9], ('rules', None, 'artefacto_ml_no_disponible'))
        predecir.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
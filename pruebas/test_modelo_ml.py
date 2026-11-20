"""Pruebas offline del clasificador v1 y sus explicaciones SHAP (#34–#36)."""
import hashlib
import json
import os
import shutil
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
        self.assertEqual(metricas['dataset_sha256'], hashlib.sha256(modelo.DATASET.read_bytes()).hexdigest())
        self.assertEqual(metricas['codigos_entrenados'], sorted(modelo.CODIGOS_ENTRENADOS))
        self.assertEqual(metricas['validacion_cruzada']['metodo'], 'StratifiedGroupKFold')
        self.assertEqual(metricas['validacion_cruzada']['particiones'], 3)
        self.assertEqual(len(metricas['validacion_cruzada']['folds']), 3)
        self.assertEqual(metricas['bootstrap_macro_f1_prueba']['plantillas'], 8)
        self.assertEqual(set(metricas['calibracion']['brier_calibrado']['por_clase']),
                         {'alta', 'media', 'baja'})
        primer_bin_alta = metricas['calibracion']['curva_confiabilidad_sin_calibrar']['alta'][0]
        self.assertLess(primer_bin_alta['confianza_media'], 0.05)
        self.assertEqual(primer_bin_alta['frecuencia_observada'], 0.0)
        self.assertEqual(sum(bin['soporte'] for bin in
                             metricas['calibracion']['curva_confiabilidad_sin_calibrar']['alta']), 138)
        self.assertEqual(set(metricas['ablacion_sensibilidad']['caracteristicas']),
                         set(modelo.CARACTERISTICAS) - {'sensibilidad'})
        self.assertTrue(metricas['integrable'])
        self.assertEqual(set(metricas['modelo']['por_clase']), {'alta', 'media', 'baja'})
        self.assertEqual(len(metricas['modelo']['matriz_confusion']), 3)

    def test_reproduce_macro_f1_y_huella_del_dataset_desde_artefacto(self):
        inferencia.cargar_modelo.cache_clear()
        try:
            bundle = inferencia.cargar_modelo()
        finally:
            inferencia.cargar_modelo.cache_clear()
        dataset = pd.read_csv(modelo.DATASET)
        prueba = dataset[dataset['particion'] == 'prueba']
        self.assertEqual(
            bundle['metrics']['dataset_sha256'], hashlib.sha256(modelo.DATASET.read_bytes()).hexdigest())
        clases, probabilidades = inferencia.predecir_probabilidades(
            bundle, prueba[list(modelo.CARACTERISTICAS)])
        predichas = [clases[indice] for indice in probabilidades.argmax(axis=1)]
        reproducida = modelo._metricas(prueba['etiqueta'], predichas, modelo.CLASES)['macro_f1']
        self.assertAlmostEqual(reproducida, bundle['metrics']['modelo']['macro_f1'], places=15)

    def test_ablacion_sensibilidad_mide_caracteristicas_reducidas(self):
        metricas = self.bundle['metrics']
        self.assertLess(metricas['ablacion_sensibilidad']['macro_f1_prueba'],
                        metricas['modelo_sin_calibrar']['macro_f1'])

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
            sha256 = modelo.guardar(self.bundle, artefacto, ficha)
            cargado = modelo.joblib.load(artefacto)
            self.assertEqual(cargado['version'], modelo.VERSION)
            self.assertEqual(cargado['metrics'], self.bundle['metrics'])
            # RC-305: guardar escribe el sha256 del modelo junto a él y en la ficha, y con esa huella carga
            self.assertEqual(sha256, hashlib.sha256(artefacto.read_bytes()).hexdigest())
            huella = Path(directorio) / 'modelo.joblib.sha256'
            self.assertEqual(huella.read_text(encoding='ascii'), '%s  modelo.joblib\n' % sha256)
            self.assertEqual(json.loads(ficha.read_text(encoding='utf-8')),
                             {**self.bundle['metrics'], 'sha256': sha256})
            inferencia.cargar_modelo.cache_clear()
            try:
                self.assertEqual(inferencia.cargar_modelo(artefacto, huella)['version'], modelo.VERSION)
            finally:
                inferencia.cargar_modelo.cache_clear()

    def test_artefacto_de_produccion_carga_con_version_integrable(self):
        inferencia.cargar_modelo.cache_clear()
        bundle = inferencia.cargar_modelo()
        self.assertEqual(bundle['version'], modelo.VERSION)
        self.assertTrue(bundle['metrics']['integrable'])
        self.assertEqual(bundle['metrics']['particionamiento'], 'por_plantilla')

    def test_huella_de_cirdan_ml_es_la_de_la_ficha_y_la_del_artefacto(self):
        # RC-305: la huella que revisa la API (cirdan/ml/, entra en la imagen) es la misma de docs/modelo_ml_v1.json
        ficha = json.loads(modelo.FICHA.read_text(encoding='utf-8'))
        calculada = hashlib.sha256(inferencia.ARTEFACTO.read_bytes()).hexdigest()
        self.assertEqual(inferencia.leer_huella(), ficha['sha256'])
        self.assertEqual(inferencia.leer_huella(), calculada)
        self.assertEqual(inferencia.HUELLA.parent, inferencia.ARTEFACTO.parent)

    def test_copia_con_un_byte_cambiado_no_se_carga(self):
        with tempfile.TemporaryDirectory() as directorio:
            copia = cambiar_un_byte(Path(directorio))
            inferencia.cargar_modelo.cache_clear()
            try:
                with mock.patch('joblib.load') as cargar_pickle, \
                        self.assertLogs('cirdan.ml.inferencia', 'WARNING') as registro, \
                        self.assertRaises(inferencia.HuellaNoCoincide):
                    inferencia.cargar_modelo(copia)
            finally:
                inferencia.cargar_modelo.cache_clear()
            cargar_pickle.assert_not_called()
            self.assertIn('no coincide', registro.output[0])

    def test_huella_ausente_o_rota_no_carga(self):
        with tempfile.TemporaryDirectory() as directorio:
            rota = Path(directorio) / 'rota.sha256'
            rota.write_text('no-es-un-sha256  modelo_v1.joblib\n', encoding='ascii')
            inferencia.cargar_modelo.cache_clear()
            try:
                with mock.patch('joblib.load') as cargar_pickle:
                    with self.assertRaises(inferencia.HuellaNoCoincide):
                        inferencia.cargar_modelo(inferencia.ARTEFACTO, rota)
                    with self.assertLogs('cirdan.ml.inferencia', level='WARNING') as registro:
                        with self.assertRaises(inferencia.HuellaNoCoincide):
                            inferencia.cargar_modelo(inferencia.ARTEFACTO, Path(directorio) / 'falta.sha256')
                    self.assertIn('falta.sha256', registro.output[0])
                    # Si falta el modelo mismo sigue el FileNotFoundError: el orquestador da 'artefacto_ml_no_disponible'
                    with self.assertRaises(FileNotFoundError):
                        inferencia.cargar_modelo(Path(directorio) / 'falta.joblib', inferencia.HUELLA)
            finally:
                inferencia.cargar_modelo.cache_clear()
            cargar_pickle.assert_not_called()

    def test_cirdan_ml_model_path_ya_no_cambia_el_modelo(self):
        # Decisión 1 en a (RC-305): solo se carga el modelo de cirdan/ml/
        with tempfile.TemporaryDirectory() as directorio:
            copia = cambiar_un_byte(Path(directorio))
            inferencia.cargar_modelo.cache_clear()
            try:
                with mock.patch.dict(os.environ, {'CIRDAN_ML_MODEL_PATH': str(copia)}):
                    self.assertEqual(inferencia.cargar_modelo()['version'], modelo.VERSION)
            finally:
                inferencia.cargar_modelo.cache_clear()

    def test_inferencia_da_severidad_confianza_y_top_tres_shap(self):
        fila = {
            'id': 'f-ml',
            'rule_code': 'outdated_software',
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
            'rule_code': 'breach_exposure',
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

    def test_inferencia_omite_codigos_que_no_entrenaron_el_modelo(self):
        fila = {
            'id': 'f-no-entrenado',
            'rule_code': 'email_in_public_commits',
            'severity': 'medium',
            'caracteristicas': {
                'tipo': 'correo_publicado',
                'antiguedad_dias': 180,
                'exposicion': 'directa',
                'sensibilidad': 'alta',
            },
        }
        self.assertEqual(inferencia.predecir(self.bundle, [fila]), {})


def cambiar_un_byte(directorio):
    """Copia el modelo del repo y le cambia un byte a la mitad."""
    copia = directorio / 'modelo_v1.joblib'
    shutil.copyfile(inferencia.ARTEFACTO, copia)
    datos = bytearray(copia.read_bytes())
    datos[len(datos) // 2] ^= 0x01
    copia.write_bytes(bytes(datos))
    return copia


class ResultadoSimulado:

    def __init__(self, filas=(), fila=None):
        self.filas = filas
        self.fila = fila

    def fetchall(self):
        return self.filas

    def fetchone(self):
        return self.fila


class ConexionSimulada:

    def __init__(self, cortes=(40, 60, 80), severidad='medium'):
        self.consultas = []
        self.cortes = cortes
        self.severidad = severidad

    def execute(self, sql, parametros=()):
        self.consultas.append((sql, parametros))
        if 'FROM scoring_rule_sets' in sql:   # cortes_del_juego (RC-237)
            medio, alto, critico = self.cortes
            return ResultadoSimulado(fila={'band_medium_from': medio, 'band_high_from': alto,
                                           'band_critical_from': critico})
        if sql.startswith('SELECT f.id::text'):
            return ResultadoSimulado([{
                'id': 'finding-1', 'rule_code': 'spf_missing', 'base_severity': 'medium', 'severity': self.severidad,
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

    def guardar(self, bundle, fallo=None, conexion=None, salida_prediccion=None):
        conexion = conexion or ConexionSimulada()
        if salida_prediccion is None:
            salida_prediccion = {
                'finding-1': {'severity': 'high', 'model_prediction': 'high', 'confidence': .91,
                              'shap': [{'feature': 'sensibilidad', 'value': 'media', 'contribution': .2}]},
            }
        with mock.patch.object(inferencia, 'cargar_modelo', side_effect=fallo) if fallo else \
                mock.patch.object(inferencia, 'cargar_modelo', return_value=bundle), \
                mock.patch.object(inferencia, 'predecir', return_value=salida_prediccion) as predecir:
            orquestador._guardar_score(conexion, 'org', 'domain', 'scan', 'ruleset', self.REGLAS, self.PESOS, False)
        return conexion, predecir

    def test_codigo_sin_prediccion_conserva_severidad_base(self):
        conexion, _ = self.guardar(
            {'version': 'v-test', 'metrics': {'integrable': True}}, salida_prediccion={})
        aporte = next(params for sql, params in conexion.consultas if 'INSERT INTO score_contributions' in sql)
        self.assertEqual(aporte[5], 'medium')

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

    def test_el_piso_sale_de_los_cortes_del_juego_del_score(self):
        # RC-237: un crítico vigente deja el dominio en el inicio de la banda alto del juego con que se guarda.
        for cortes, piso in (((40, 60, 80), 60), ((50, 70, 85), 70)):
            conexion, _ = self.guardar(None, FileNotFoundError(), ConexionSimulada(cortes, 'critical'))
            consulta = next(params for sql, params in conexion.consultas if 'FROM scoring_rule_sets' in sql)
            self.assertEqual(consulta, ('ruleset',))
            score = next(params for sql, params in conexion.consultas if 'INSERT INTO domain_scores' in sql)
            self.assertEqual(score[4], piso, cortes)

    def test_modelo_con_un_byte_cambiado_no_carga_y_el_score_sale_por_reglas(self):
        cargar_real = inferencia.cargar_modelo
        with tempfile.TemporaryDirectory() as directorio:
            copia = cambiar_un_byte(Path(directorio))
            cargar_real.cache_clear()
            try:
                with mock.patch('joblib.load') as cargar_pickle, \
                        self.assertLogs('cirdan.ml.inferencia', 'WARNING') as registro:
                    conexion, predecir = self.guardar(None, lambda: cargar_real(copia))
            finally:
                cargar_real.cache_clear()
        cargar_pickle.assert_not_called()
        predecir.assert_not_called()
        self.assertIn('no coincide', registro.output[0])
        score = next(params for sql, params in conexion.consultas if 'INSERT INTO domain_scores' in sql)
        self.assertEqual(score[6:9], ('rules', None, 'inferencia_ml_no_disponible'))
        aporte = next(params for sql, params in conexion.consultas if 'INSERT INTO score_contributions' in sql)
        self.assertEqual(aporte[5], 'medium')


if __name__ == '__main__':
    unittest.main(verbosity=2)
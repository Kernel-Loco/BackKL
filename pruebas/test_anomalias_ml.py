"""Pruebas offline del detector experimental de perfiles raros (#67)."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cirdan.ml import anomalias


class DetectorAnomalias(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.bundle = anomalias.entrenar()

    def test_entrena_solo_perfiles_alta_y_no_afirma_validacion(self):
        metricas = self.bundle['metrics']
        self.assertEqual(metricas['filas_entrenamiento'], 72)
        self.assertEqual(len(metricas['plantillas_entrenamiento']), 3)
        self.assertIsNone(metricas['umbral'])
        self.assertFalse(metricas['afecta_severidad_o_score'])
        self.assertIn('no disponible', metricas['validacion_anomalias'])
        self.assertEqual(metricas['dataset_sha256'],
                         hashlib.sha256(anomalias.DATASET.read_bytes()).hexdigest())

    def test_score_continuo_solo_para_hallazgos_high_y_critical(self):
        caracteristicas = {
            'tipo': 'software_desactualizado',
            'antiguedad_dias': 180,
            'exposicion': 'directa',
            'sensibilidad': 'alta',
        }
        hallazgos = [
            {'id': 'high', 'severity': 'high', 'caracteristicas': caracteristicas},
            {'id': 'critical', 'severity': 'critical', 'caracteristicas': caracteristicas},
            {'id': 'medium', 'severity': 'medium', 'caracteristicas': caracteristicas},
        ]
        scores = anomalias.puntuar(self.bundle, hallazgos)
        self.assertEqual(set(scores), {'high', 'critical'})
        self.assertTrue(all(isinstance(valor, float) for valor in scores.values()))

    def test_rechaza_caracteristicas_incompletas(self):
        with self.assertRaisesRegex(ValueError, 'cuatro características'):
            anomalias.puntuar(self.bundle, [
                {'id': 'high', 'severity': 'high', 'caracteristicas': {'tipo': 'x'}}])

    def test_artefacto_del_repo_coincide_con_huella_y_ficha(self):
        ficha = json.loads(anomalias.FICHA.read_text(encoding='utf-8'))
        sha256 = hashlib.sha256(anomalias.ARTEFACTO.read_bytes()).hexdigest()
        self.assertEqual(ficha['sha256'], sha256)
        cargado = anomalias.cargar_modelo()
        self.assertEqual(cargado['version'], anomalias.VERSION)
        self.assertEqual(ficha, {**cargado['metrics'], 'sha256': sha256})

    def test_artefacto_usa_huella_y_rechaza_cambios(self):
        with tempfile.TemporaryDirectory() as directorio:
            artefacto = Path(directorio) / 'anomalias.joblib'
            ficha = Path(directorio) / 'anomalias.json'
            sha256 = anomalias.guardar(self.bundle, artefacto, ficha)
            huella = Path(directorio) / 'anomalias.joblib.sha256'
            self.assertEqual(sha256, hashlib.sha256(artefacto.read_bytes()).hexdigest())
            self.assertEqual(json.loads(ficha.read_text(encoding='utf-8'))['sha256'], sha256)
            self.assertEqual(anomalias.cargar_modelo(artefacto, huella)['version'], anomalias.VERSION)
            datos = bytearray(artefacto.read_bytes())
            datos[len(datos) // 2] ^= 1
            artefacto.write_bytes(datos)
            with self.assertRaisesRegex(ValueError, 'no coincide'):
                anomalias.cargar_modelo(artefacto, huella)


if __name__ == '__main__':
    unittest.main(verbosity=2)

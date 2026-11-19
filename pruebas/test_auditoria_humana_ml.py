"""Pruebas offline del flujo futuro de evaluación humana ciega (#67)."""
import csv
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from cirdan.ml import auditoria_humana, modelo


class AuditoriaHumana(unittest.TestCase):

    def test_muestra_ciega_y_comparacion_sin_modificar_dataset(self):
        dataset = pd.read_csv(modelo.DATASET)
        referencia = dict(zip(dataset.loc[dataset['particion'] == 'prueba', 'id'],
                              dataset.loc[dataset['particion'] == 'prueba', 'etiqueta']))
        with tempfile.TemporaryDirectory() as directorio:
            muestra = Path(directorio) / 'muestra.csv'
            informe = Path(directorio) / 'reporte.json'
            resultado = auditoria_humana.crear_muestra(salida=muestra)
            self.assertEqual(resultado['filas'], 45)
            with muestra.open(encoding='utf-8', newline='') as archivo:
                lector = csv.DictReader(archivo)
                filas = list(lector)
                self.assertNotIn('rule_code', lector.fieldnames)
                self.assertNotIn('severity', lector.fieldnames)
                self.assertNotIn('plantilla', lector.fieldnames)
            self.assertTrue(all(not fila['etiqueta'] and not fila['nota'] for fila in filas))

            for fila in filas:
                fila['etiqueta'] = referencia[fila['id']]
            with muestra.open('w', encoding='utf-8', newline='') as archivo:
                escritor = csv.DictWriter(archivo, fieldnames=filas[0].keys(), lineterminator='\n')
                escritor.writeheader()
                escritor.writerows(filas)
            comparacion = auditoria_humana.comparar(muestra, informe=informe)
            self.assertEqual(comparacion['filas'], 45)
            self.assertEqual(comparacion['acuerdo']['exactitud'], 1.0)
            self.assertEqual(comparacion['acuerdo']['cohen_kappa'], 1.0)
            self.assertTrue(informe.is_file())


if __name__ == '__main__':
    unittest.main(verbosity=2)

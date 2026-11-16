"""El CI corre todos los archivos de pruebas (auditoría del 8 nov, fila 42). Sin base ni red.

    python -m unittest -v pruebas/test_ci.py

test_pesos_configurables.py entró el 5 nov y .github/workflows/pruebas.yml nunca lo corrió: una regresión en
validar_pesos de PUT /scoring/weights se fusionaba con el CI en verde.
"""
import re
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
CI = RAIZ / '.github' / 'workflows' / 'pruebas.yml'


class TodasEnElCi(unittest.TestCase):

    def test_1_cada_archivo_de_pruebas_esta_en_el_ci(self):
        # Cuenta solo el archivo completo (pruebas/test_x.py). pruebas.test_x.Clase corre una clase y no basta
        texto = CI.read_text(encoding='utf-8-sig')
        nombrados = set(re.findall(r'pruebas/(test_\w+)\.py', texto))
        archivos = {p.stem for p in (RAIZ / 'pruebas').glob('test_*.py')}
        self.assertTrue(archivos)
        self.assertEqual(sorted(archivos - nombrados), [], 'pruebas que el CI no corre: súmalas a pruebas.yml')

    def test_2_lo_que_nombra_el_ci_existe(self):
        texto = CI.read_text(encoding='utf-8-sig')
        for nombre in sorted(set(re.findall(r'pruebas[/.](test_\w+)', texto))):
            self.assertTrue((RAIZ / 'pruebas' / (nombre + '.py')).is_file(), nombre)


if __name__ == '__main__':
    unittest.main(verbosity=2)

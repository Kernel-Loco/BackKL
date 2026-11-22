"""El CI corre todos los archivos de pruebas (auditoría del 8 nov, fila 42). Sin base ni red.

    python -m unittest -v pruebas/test_ci.py

test_pesos_configurables.py entró el 5 nov y .github/workflows/pruebas.yml nunca lo corrió: una regresión en
validar_pesos de PUT /scoring/weights se fusionaba con el CI en verde.
"""
import re
import shutil
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
CI = RAIZ / '.github' / 'workflows' / 'pruebas.yml'

# El paso 'Pruebas sin base ni red' corre con el Python de setup-python, sin pip install. Este programa importa
# cada módulo de prueba con python -S -E, sin site-packages: solo la biblioteca estándar, cirdan y pruebas, como en ese runner.
SOLO_ESTANDAR = r"""
import importlib, sys, traceback
fallas = []
for modulo in sys.argv[1:]:
    try:
        importlib.import_module(modulo)
    except Exception:
        fallas.append(modulo + ': ' + traceback.format_exc().strip().splitlines()[-1])
print('\n'.join(fallas))
sys.exit(1 if fallas else 0)
"""


def paso(nombre):
    """Texto del paso del workflow con ese nombre, hasta el siguiente '- name:'."""
    texto = CI.read_text(encoding='utf-8-sig')
    inicio = texto.index('- name: ' + nombre)
    fin = texto.find('- name:', inicio + 1)
    return texto[inicio:fin if fin != -1 else len(texto)]


@unittest.skipUnless(shutil.which('sh'), 'sin sh')
class ResultadoDelEnlace(unittest.TestCase):
    """La línea del paso 'Enlace al correo' que exige el OK de unittest (#28, RC-63): un aviso de Python después del OK
    no la tumba, y un skip o una falla sí."""

    def revisar(self, err):
        (linea,) = [l.strip() for l in paso('Enlace al correo').splitlines() if 'enlace.err' in l and 'OK' in l]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'enlace.err').write_text(err, encoding='utf-8')
            return subprocess.run(['sh', '-c', linea], cwd=tmp, capture_output=True, timeout=30).returncode

    def test_4_ok_con_un_aviso_despues(self):
        aviso = ('/usr/local/lib/python3.15/site-packages/psycopg/_connection_base.py:153: ResourceWarning: '
                 '<psycopg.Connection object at 0x7f> was deleted while still open\n')
        self.assertEqual(self.revisar('test_1 ... ok\n\nRan 8 tests in 10.3s\n\nOK\n' + aviso), 0)
        self.assertEqual(self.revisar('Ran 8 tests in 10.3s\n\nOK\n'), 0)

    def test_5_skip_o_falla_no_pasan(self):
        for err in ('Ran 8 tests in 0.0s\n\nOK (skipped=8)\n', 'Ran 8 tests\n\nFAILED (failures=1)\n',
                    'Traceback (most recent call last):\n', ''):
            with self.subTest(err=err[-25:]):
                self.assertNotEqual(self.revisar(err), 0)


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

    def test_3_lo_que_corre_sin_base_no_pide_paquetes(self):
        # test_pesos_configurables importa cirdan.score.configuracion, que importa psycopg: en ese paso el job
        # salía en rojo con ModuleNotFoundError (revisión de riesgo del 15 nov, #7)
        modulos = ['pruebas.' + n for n in re.findall(r'pruebas/(test_\w+)\.py', paso('Pruebas sin base ni red'))]
        self.assertIn('pruebas.test_ci', modulos)
        corrida = subprocess.run([sys.executable, '-S', '-E', '-c', SOLO_ESTANDAR, *modulos], cwd=RAIZ, capture_output=True,
                                 text=True, encoding='utf-8', timeout=120)
        self.assertEqual(corrida.returncode, 0, 'piden paquetes que el runner no trae, van dentro del contenedor:\n'
                         + corrida.stdout + corrida.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)

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
        (linea,) = [x.strip() for x in paso('Enlace al correo').splitlines() if 'enlace.err' in x and 'OK' in x]
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


SEGURIDAD = RAIZ / '.github' / 'workflows' / 'seguridad.yml'


def paso_de(archivo, nombre):
    texto = archivo.read_text(encoding='utf-8-sig')
    inicio = texto.index('- name: ' + nombre)
    fin = texto.find('- name:', inicio + 1)
    return texto[inicio:fin if fin != -1 else len(texto)]


class JobDeSeguridad(unittest.TestCase):
    """El job seguridad de RC-254 no se afloja: gitleaks sobre toda la historia, bandit, pip-audit y ruff en rojo."""

    def test_6_corre_en_cada_pr_y_push_a_dev_y_main(self):
        texto = SEGURIDAD.read_text(encoding='utf-8-sig')
        self.assertIn('  seguridad:' + chr(10), texto)
        self.assertEqual(texto.count('branches: [dev, main]'), 2)
        self.assertIn('fetch-depth: 0', texto)
        self.assertNotIn('continue-on-error', texto)

    def test_7_gitleaks_toda_la_historia_con_la_config_del_repo(self):
        gitleaks = paso_de(SEGURIDAD, 'gitleaks sobre el repo')
        for parte in ('zricethezav/gitleaks:v8.21.2@sha256:', '--network none', ' git /repo ',
                      '--config /repo/.gitleaks.toml', '--gitleaks-ignore-path /repo/.gitleaksignore',
                      '--ignore-gitleaks-allow', '--log-opts="--full-history HEAD"', '--redact'):
            self.assertIn(parte, gitleaks)
        self.assertNotIn('--exit-code 0', gitleaks)
        # La autoprueba de la config corre antes que la historia, con la misma imagen
        texto = SEGURIDAD.read_text(encoding='utf-8-sig')
        self.assertLess(texto.index('run: python3 pruebas/gitleaks_autoprueba.py'),
                        texto.index('- name: gitleaks sobre el repo'))
        from pruebas import gitleaks_autoprueba
        self.assertIn(gitleaks_autoprueba.IMAGEN, gitleaks)

    def test_8_bandit_pip_audit_y_ruff_frenan(self):
        bandit = paso_de(SEGURIDAD, 'bandit sobre cirdan/ (shell')
        self.assertIn('bandit -r cirdan -q --ignore-nosec -t B602,B604,B605,B609', bandit)
        self.assertIn('bandit -r cirdan -q --ignore-nosec --severity-level high', bandit)
        self.assertNotIn('--exit-zero', bandit)
        auditoria = paso_de(SEGURIDAD, 'pip-audit')
        self.assertIn('pip-audit -r requirements.txt', auditoria)
        self.assertNotIn('--no-deps', auditoria)
        ruff = paso_de(SEGURIDAD, 'ruff sobre los .py que cambian')
        self.assertIn('ruff check --no-cache --select E4,E7,E9,F', ruff)
        self.assertNotIn('--exit-zero', ruff)

    def test_9_la_excepcion_de_gitleaks_solo_vale_en_fixtures(self):
        import tomllib
        config = tomllib.loads((RAIZ / '.gitleaks.toml').read_text(encoding='utf-8'))
        (regla,) = [r for r in config['rules'] if r['id'] == 'lowtide-token-falso-fuera-de-fixtures']
        self.assertTrue(re.search(regla['regex'], 'TOKEN = "CIRDAN_' + 'FAKE_ghp_0123456789"'))
        # El secreto es solo el prefijo: la allowlist global de gitleaks ('false', 'null' al final) no lo salta
        self.assertEqual(regla['secretGroup'], 1)
        self.assertEqual(re.search(regla['regex'], 'CIRDAN_' + 'FAKE_xfalsex99999').group(1), 'CIRDAN_FAKE_')
        self.assertEqual(regla['allowlist']['paths'], ['^pruebas/fixtures/'])
        self.assertTrue(re.search(regla['allowlist']['paths'][0], 'pruebas/fixtures/tokens.txt'))
        self.assertFalse(re.search(regla['allowlist']['paths'][0], 'pruebas/test_x.py'))
        # Sin [allowlist] global: con useDefault heredaría '(?i)^true|false|null$' sobre la línea entera
        self.assertNotIn('allowlist', config)
        # Las huellas sha256 solo se saltan dentro de generic-api-key y con la forma exacta de la línea
        (generica,) = [r for r in config['rules'] if r['id'] == 'generic-api-key']
        self.assertNotIn('regex', generica)
        (excepcion,) = generica['allowlists']
        self.assertEqual(excepcion['regexTarget'], 'line')
        (forma,) = excepcion['regexes']
        huella = "    'db/migraciones/016_api_key_lookup.sql': '%s'," % ('ab' * 32)
        self.assertTrue(re.search(forma, huella))
        self.assertTrue(re.search(forma, huella + chr(13)))
        for otra in (huella + '  # false', 'api_key = "%s"' % ('ab' * 32), "    'docs/x.sql': '%s'," % ('ab' * 32)):
            with self.subTest(linea=otra[-30:]):
                self.assertFalse(re.search(forma, otra))


class PilaDesechable(unittest.TestCase):
    """pruebas/pila.py (RC-254, control 8.31): en una PC las pruebas de base y API no corren contra la pila de desarrollo."""

    DESECHABLE = {'CIRDAN_TEST_DB_CONTAINER': 'backkl-pruebas-pg16', 'CIRDAN_TEST_VALKEY': 'backkl-pruebas-valkey',
                  'CIRDAN_TEST_API_CONTAINER': 'backkl-pruebas-api', 'CIRDAN_TEST_BASE': 'http://127.0.0.1:8001'}

    def test_10_sin_variables_falla_en_una_pc(self):
        from pruebas.pila import exigir_desechable
        with self.assertRaisesRegex(RuntimeError, 'cirdan-pg16'):
            exigir_desechable({}, en_contenedor=False)
        for nombre in self.DESECHABLE:
            with self.subTest(falta=nombre):
                entorno = {k: v for k, v in self.DESECHABLE.items() if k != nombre}
                with self.assertRaises(RuntimeError):
                    exigir_desechable(entorno, en_contenedor=False)
        with self.assertRaises(RuntimeError):
            exigir_desechable(dict(self.DESECHABLE, CIRDAN_TEST_BASE='http://localhost:8000'), en_contenedor=False)

    def test_11_pasa_con_el_compose_desechable_en_el_ci_o_en_un_contenedor_marcado(self):
        from pruebas.pila import exigir_desechable
        exigir_desechable(self.DESECHABLE, en_contenedor=False)
        exigir_desechable({'GITHUB_ACTIONS': 'true'}, en_contenedor=False)
        exigir_desechable({'CIRDAN_TEST_DB_ISOLATED': 'true'}, en_contenedor=True)
        # Un contenedor de la pila de desarrollo (docker compose run api ... sin el compose desechable) frena
        for entorno in ({}, {'CIRDAN_TEST_DB_ISOLATED': '1'}, dict(self.DESECHABLE)):
            with self.subTest(entorno=entorno), self.assertRaisesRegex(RuntimeError, 'CIRDAN_TEST_DB_ISOLATED'):
                exigir_desechable(entorno, en_contenedor=True)
        # En una PC la marca no basta: ahí mandan los nombres
        with self.assertRaises(RuntimeError):
            exigir_desechable({'CIRDAN_TEST_DB_ISOLATED': 'true'}, en_contenedor=False)

    def test_11b_contenedor_elegido_con_otra_variable(self):
        from pruebas.pila import exigir_contenedor
        for nombre in ('cirdan-pg16', ' cirdan-pg16 ', 'cirdan-valkey', 'cirdan-api'):
            with self.subTest(nombre=nombre), self.assertRaises(RuntimeError):
                exigir_contenedor(nombre, {}, en_contenedor=False)
        exigir_contenedor('lote14-x-pg16', {}, en_contenedor=False)
        exigir_contenedor('cirdan-pg16', {'GITHUB_ACTIONS': 'true'}, en_contenedor=False)
        with self.assertRaises(RuntimeError):
            exigir_contenedor('lote14-x-pg16', {}, en_contenedor=True)

    def test_12_el_compose_desechable_usa_esos_nombres_y_puertos(self):
        texto = (RAIZ / 'docker-compose.pruebas.yml').read_text(encoding='utf-8')
        for parte in ('container_name: backkl-pruebas-pg16', 'container_name: backkl-pruebas-valkey',
                      'container_name: backkl-pruebas-api', '"127.0.0.1:8001:8000"', 'profiles: !override'):
            self.assertIn(parte, texto)
        self.assertNotIn('cirdan-pg16', texto.split('services:')[1])
        self.assertIn('CIRDAN_TEST_DB_ISOLATED: "true"', texto.split('  api:')[1].split('  programador:')[0])
        # Los demás lugares donde corren pruebas dentro de un contenedor llevan la marca
        self.assertIn('CIRDAN_TEST_DB_ISOLATED: "true"',
                      (RAIZ / 'pruebas' / 'enlace' / 'docker-compose.yml').read_text(encoding='utf-8'))
        self.assertIn('-e CIRDAN_TEST_DB_ISOLATED=true', paso('Pruebas dentro del contenedor'))

    def test_13_todo_docker_exec_de_las_pruebas_pasa_por_el_candado(self):
        import ast
        candados = {'exigir_desechable', 'exigir_contenedor'}

        def es_docker(nodo):
            return (isinstance(nodo, ast.List) and len(nodo.elts) >= 2
                    and all(isinstance(e, ast.Constant) for e in nodo.elts[:2])
                    and tuple(e.value for e in nodo.elts[:2]) in (('docker', 'exec'), ('docker', 'logs')))

        def llama_candado(nodo):
            return isinstance(nodo, ast.Call) and getattr(nodo.func, 'id', getattr(nodo.func, 'attr', None)) in candados

        sin_candado, con_docker = [], 0
        for archivo in sorted((RAIZ / 'pruebas').glob('*.py')):
            arbol = ast.parse(archivo.read_text(encoding='utf-8'))
            for funcion in ast.walk(arbol):
                if not isinstance(funcion, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not any(es_docker(n) for n in ast.walk(funcion)):
                    continue
                con_docker += 1
                if not any(llama_candado(n) for n in ast.walk(funcion)):
                    sin_candado.append('%s:%d %s' % (archivo.name, funcion.lineno, funcion.name))
            # Fuera de una función, un docker exec correría al importar, antes de cualquier candado
            for nodo in arbol.body:
                if not isinstance(nodo, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if any(es_docker(n) for n in ast.walk(nodo)):
                        sin_candado.append('%s:%d (al importar)' % (archivo.name, nodo.lineno))
        self.assertGreater(con_docker, 10)
        self.assertEqual(sin_candado, [], 'docker exec sin exigir_desechable() ni exigir_contenedor() antes')


if __name__ == '__main__':
    unittest.main(verbosity=2)

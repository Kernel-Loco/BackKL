"""El CI corre todos los archivos de pruebas (auditoría del 8 nov, fila 42). Sin base ni red.

    python -m unittest -v pruebas/test_ci.py

test_pesos_configurables.py entró el 5 nov y .github/workflows/pruebas.yml nunca lo corrió: una regresión en
validar_pesos de PUT /scoring/weights se fusionaba con el CI en verde.

JobDeSeguridad (#136, RC-254) revisa que el CI de seguridad no se afloje sin que se note.
"""
import hashlib
import re
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
CI = RAIZ / '.github' / 'workflows' / 'pruebas.yml'
SEGURIDAD = RAIZ / '.github' / 'workflows' / 'seguridad.yml'
# La configuración del recolector de GitHub (#16) no cambia con el gitleaks del repo. Fines de línea normalizados,
# como HUELLAS_DB de test_catalogo_reglas.py.
GITLEAKS_RECOLECTOR = '9e3c392f39ca843f16c7336b82152fc44db84878f5c28c4f2d98bfbb86510159'
HUELLA_IGNORADA = re.compile(r'^[0-9a-f]{40}:[^:\s]+:[\w-]+:\d+$')

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


def paso_de_seguridad(nombre):
    """Texto del paso de seguridad.yml con ese nombre, hasta el siguiente paso."""
    texto = SEGURIDAD.read_text(encoding='utf-8')
    inicio = texto.index('- name: ' + nombre)
    fin = re.search(r'\n\s*(?:#.*\n\s*)*- (?:name|uses):', texto[inicio + 1:])
    return texto[inicio:inicio + 1 + fin.start() if fin else len(texto)]


class JobDeSeguridad(unittest.TestCase):
    """#136 (RC-254): el job de seguridad falla de verdad y su configuración no se afloja sin que se note."""

    def test_4_gitleaks_bandit_pip_audit_y_ruff_frenan(self):
        flujo = SEGURIDAD.read_text(encoding='utf-8')
        self.assertIn('fetch-depth: 0', flujo)  # gitleaks revisa todo el historial y ruff compara con la rama base
        version = re.search(r'rev: (v[\d.]+)', (RAIZ / '.pre-commit-config.yaml').read_text(encoding='utf-8')).group(1)
        gitleaks = paso_de_seguridad('gitleaks sobre el repo y su historial')
        for parte in ('zricethezav/gitleaks:' + version, 'git /repo', '--config /repo/.gitleaks.toml',
                      '--gitleaks-ignore-path /repo/.gitleaksignore'):
            with self.subTest(gitleaks=parte):
                self.assertIn(parte, gitleaks)
        bandit = paso_de_seguridad('bandit sobre cirdan/ (shell y severidad alta)')
        self.assertIn('-t B602,B604,B605,B609', bandit)
        self.assertIn('--severity-level high', bandit)
        auditoria = paso_de_seguridad('pip-audit sobre requirements.txt y sus dependencias')
        self.assertIn('pip-audit -r requirements.txt --strict', auditoria)
        self.assertNotIn('--no-deps', auditoria)  # las dependencias indirectas también se revisan
        self.assertIn('ruff check', paso_de_seguridad('ruff sobre los .py que cambia el PR o el push'))
        # Solo los dos avisos dejan seguir con errores.
        self.assertEqual(flujo.count('continue-on-error'), 1)
        self.assertIn('continue-on-error: true', paso_de_seguridad('ruff (aviso)'))
        self.assertEqual(flujo.count('--exit-zero'), 1)
        self.assertIn('--exit-zero', paso_de_seguridad('bandit sobre cirdan/ (todo, como aviso)'))

    def test_5_un_token_falso_solo_vive_en_fixtures(self):
        with open(RAIZ / '.gitleaks.toml', 'rb') as f:
            config = tomllib.load(f)
        self.assertEqual(config['extend'], {'useDefault': True})
        regla, = config['rules']
        self.assertIn('CIRDAN_FAKE_', regla['regex'])
        self.assertEqual(regla['allowlist'], {'paths': ['^pruebas/fixtures/']})
        # La única excepción global son las líneas de huellas sha256 de migraciones y semillas.
        global_ = config['allowlist']
        self.assertNotIn('paths', global_)
        self.assertEqual(global_['regexTarget'], 'line')
        expresion, = global_['regexes']
        self.assertTrue(expresion.startswith('^') and expresion.endswith('$'))
        self.assertIn('[0-9a-f]{64}', expresion)

    def test_6_cada_huella_ignorada_trae_su_motivo(self):
        motivo = False
        for linea in (RAIZ / '.gitleaksignore').read_text(encoding='utf-8').splitlines():
            if not linea.strip():
                motivo = False  # un bloque nuevo pide su propio comentario
            elif linea.startswith('#'):
                motivo = True
            else:
                with self.subTest(huella=linea):
                    self.assertRegex(linea, HUELLA_IGNORADA)
                    self.assertTrue(motivo, 'falta el comentario con el motivo arriba de la huella')

    def test_7_configuracion_del_recolector_sin_cambios(self):
        crudo = (RAIZ / 'cirdan' / 'recolectores' / 'gitleaks_cirdan.toml').read_bytes().replace(b'\r\n', b'\n')
        self.assertEqual(hashlib.sha256(crudo).hexdigest(), GITLEAKS_RECOLECTOR)


if __name__ == '__main__':
    unittest.main(verbosity=2)

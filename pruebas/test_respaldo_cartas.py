"""Integración del respaldo completo de cartas, su llave y la base (RC-28, RC-339)."""
import base64
import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
RESPALDO = RAIZ / 'db' / 'respaldo'
PDF = b'%PDF-1.4\nCIRDAN_TEST_CARTA\n%%EOF\n'
ORG_ID = '10000000-0000-4000-8000-000000000001'
DOMAIN_ID = '30000000-0000-4000-8000-000000000001'
CONTENEDOR_BASE = (os.environ.get('RESPALDO_CONTENEDOR') or '').strip() or (
    'cirdan-pg16' if (os.environ.get('CI') or '').strip().lower() in ('true', '1') else None)
CONTENEDOR_CARTAS = (os.environ.get('RESPALDO_CARTAS_CONTENEDOR') or '').strip() or (
    'cirdan-api' if (os.environ.get('CI') or '').strip().lower() in ('true', '1') else None)
PATRON = re.compile(r'^cirdan_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}\.backup\.age$')


def correr(argumentos, env=None, entrada=None):
    return subprocess.run(argumentos, input=entrada, capture_output=True, text=True, encoding='utf-8',
                          errors='replace', env={**os.environ, **(env or {})})


class PaqueteSeguro(unittest.TestCase):
    def test_solo_extrae_los_archivos_cifrados_esperados(self):
        with tempfile.TemporaryDirectory() as temporal:
            raiz = Path(temporal)
            archivo = raiz / 'paquete.tar'
            salida = raiz / 'salida'
            salida.mkdir(mode=0o700)
            with tarfile.open(archivo, 'w') as tar:
                for nombre in ('cirdan.dump.age', 'cartas.tar.age', 'carta.key.age'):
                    datos = (nombre + '-cifrado').encode()
                    info = tarfile.TarInfo(nombre)
                    info.size = len(datos)
                    tar.addfile(info, io.BytesIO(datos))

            resultado = correr(['python', str(RESPALDO / 'paquete.py'), 'extraer', str(archivo), str(salida)])

            self.assertEqual(resultado.returncode, 0, resultado.stderr)
            self.assertEqual({ruta.name for ruta in salida.iterdir()},
                             {'cirdan.dump.age', 'cartas.tar.age', 'carta.key.age'})
            if os.name != 'nt':
                self.assertTrue(all(ruta.stat().st_mode & 0o777 == 0o600 for ruta in salida.iterdir()))

    def test_rechaza_rutas_y_enlaces_en_el_archivo_de_cartas(self):
        with tempfile.TemporaryDirectory() as temporal:
            raiz = Path(temporal)
            archivo = raiz / 'cartas.tar'
            salida = raiz / 'cartas'
            salida.mkdir(mode=0o700)
            with tarfile.open(archivo, 'w') as tar:
                info = tarfile.TarInfo('../fuera.lt1')
                info.size = 31
                tar.addfile(info, io.BytesIO(b'LT1' + b'x' * 28))
            resultado = correr(['python', str(RESPALDO / 'paquete.py'), 'cartas', str(archivo), str(salida)])
            self.assertNotEqual(resultado.returncode, 0)
            self.assertFalse((raiz / 'fuera.lt1').exists())

            archivo_enlace = raiz / 'enlace.tar'
            with tarfile.open(archivo_enlace, 'w') as tar:
                info = tarfile.TarInfo('a' * 32 + '.lt1')
                info.type = tarfile.SYMTYPE
                info.linkname = '../fuera.lt1'
                tar.addfile(info)
            resultado = correr(['python', str(RESPALDO / 'paquete.py'), 'cartas',
                                str(archivo_enlace), str(salida)])
            self.assertNotEqual(resultado.returncode, 0)
            self.assertFalse((raiz / 'fuera.lt1').exists())

    def test_valida_llave_base64_url_safe_de_32_bytes(self):
        with tempfile.TemporaryDirectory() as temporal:
            llave = Path(temporal) / 'llave'
            llave.write_text(base64.urlsafe_b64encode(b'k' * 32).decode('ascii'), encoding='ascii')
            bien = correr(['python', str(RESPALDO / 'paquete.py'), 'llave', str(llave)])
            self.assertEqual(bien.returncode, 0, bien.stderr)
            llave.write_text(base64.urlsafe_b64encode(b'k' * 31).decode('ascii'), encoding='ascii')
            mal = correr(['python', str(RESPALDO / 'paquete.py'), 'llave', str(llave)])
            self.assertNotEqual(mal.returncode, 0)


@unittest.skipUnless(shutil.which('bash') and shutil.which('age') and shutil.which('docker'),
                     'faltan bash, age o docker')
@unittest.skipUnless(CONTENEDOR_BASE and CONTENEDOR_CARTAS,
                     'fuera del CI hay que nombrar una base y API de una pila aislada')
class RespaldoCartas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporal = Path(tempfile.mkdtemp(prefix='respaldo_cartas_'))
        cls.db = 'cirdan_prueba_cartas_%d' % os.getpid()
        cls.volumen = 'prueba-cartas-%d' % os.getpid()
        cls.llave_age = cls.temporal / 'age.txt'
        subprocess.run(['age-keygen', '-o', str(cls.llave_age)], check=True, capture_output=True)
        cls.identidad = cls.llave_age.read_text(encoding='ascii')
        cls.publica = subprocess.run(['age-keygen', '-y', str(cls.llave_age)], check=True, capture_output=True,
                                     text=True, encoding='ascii').stdout.strip()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'volumen'):
            subprocess.run(['docker', 'volume', 'rm', cls.volumen], capture_output=True, check=False)
        shutil.rmtree(cls.temporal, ignore_errors=True)
        if hasattr(cls, 'db') and CONTENEDOR_BASE:
            subprocess.run(
                ['docker', 'exec', CONTENEDOR_BASE, 'sh', '-c',
                 'psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 -c \'DROP DATABASE IF EXISTS "%s"\'' % cls.db],
                capture_output=True, check=False)

    def _carta_en_api(self, codigo):
        return correr(['docker', 'exec', CONTENEDOR_CARTAS, 'python', '-c', codigo])

    def _conteos(self, base):
        return subprocess.run(
            ['docker', 'exec', '-i', '-e', 'BASE=' + base, CONTENEDOR_BASE, 'sh', '-c',
             'exec psql -U "$POSTGRES_USER" -d "$BASE" -X -q -At -v ON_ERROR_STOP=1'],
            input=(RAIZ / 'db' / 'respaldo' / 'conteos.sql').read_text(encoding='utf-8'),
            capture_output=True, text=True, encoding='utf-8', check=True).stdout.strip()

    def test_respaldar_y_restaurar_base_cartas_y_llave(self):
        crear = (
            'from cirdan.cartas import guardar; '
            'print(guardar(%r, %r, %r)[0])' % (PDF, ORG_ID, DOMAIN_ID)
        )
        guardada = self._carta_en_api(crear)
        self.assertEqual(guardada.returncode, 0, guardada.stderr)
        nombre = guardada.stdout.strip()
        self.assertRegex(nombre, r'^[0-9a-f]{32}\.lt1$')
        self.addCleanup(self._carta_en_api,
                        'import os; os.unlink(os.path.join(os.environ["CARTA_STORAGE_DIR"], %r))' % nombre)

        leer_llave = (
            'import base64, sys; from cirdan.cartas import _key; '
            'sys.stdout.write(base64.urlsafe_b64encode(_key()).decode("ascii"))'
        )
        llave_origen = self._carta_en_api(leer_llave)
        self.assertEqual(llave_origen.returncode, 0, llave_origen.stderr)
        self.assertEqual(len(base64.urlsafe_b64decode(llave_origen.stdout)), 32)

        antes = self._conteos('cirdan')
        carpeta = self.temporal / 'respaldos'
        configuracion = self.temporal / 'respaldo.conf'
        configuracion.write_text(
            'CONTENEDOR_BASE=%s\nCONTENEDOR_CARTAS=%s\nCARPETA=%s\nRECEPTOR_AGE=%s\nSUBIR=0\nRETENCION=7\n'
            % (CONTENEDOR_BASE, CONTENEDOR_CARTAS, carpeta, self.publica),
            encoding='ascii')
        configuracion.chmod(0o600)
        creado = correr(['bash', str(RESPALDO / 'respaldar.sh')],
                        env={'RESPALDO_CONF': str(configuracion)})
        self.assertEqual(creado.returncode, 0, creado.stderr)
        nombres = sorted(nombre for nombre in os.listdir(carpeta) if PATRON.fullmatch(nombre))
        self.assertEqual(len(nombres), 1, nombres)
        paquete = carpeta / nombres[0]
        self.assertTrue(paquete.read_bytes().startswith(b'age-encryption.org/v1'))
        self.assertNotIn(PDF, paquete.read_bytes())
        self.assertNotIn(llave_origen.stdout.encode('ascii'), paquete.read_bytes())

        binarios = self.temporal / 'bin'
        binarios.mkdir()
        llave_restaurada = self.temporal / 'llave-restaurada.txt'
        az_falso = binarios / 'az'
        az_falso.write_text(
            '#!/usr/bin/env python3\n'
            'import os, shutil, sys\n'
            'args = sys.argv[1:]\n'
            'shutil.copyfile(args[args.index("--file") + 1], os.environ["AZ_FAKE_KEY_OUTPUT"])\n'
            'print("https://fake-vault.vault.azure.net/secrets/carta-key/0123456789abcdef0123456789abcdef")\n',
            encoding='utf-8')
        az_falso.chmod(0o755)
        destino_path = str(binarios) + os.pathsep + os.environ.get('PATH', '')
        restaurado = correr(
            ['bash', str(RESPALDO / 'restaurar_completo.sh'), str(paquete), CONTENEDOR_BASE,
             CONTENEDOR_CARTAS, self.db, self.volumen, 'fake-vault', 'carta-key'],
            env={'AGE_IDENTIDAD': str(self.llave_age), 'PATH': destino_path,
                 'AZ_FAKE_KEY_OUTPUT': str(llave_restaurada)})
        self.assertEqual(restaurado.returncode, 0, restaurado.stderr)
        self.assertNotIn(llave_origen.stdout, restaurado.stdout + restaurado.stderr)
        self.assertEqual(llave_restaurada.read_text(encoding='ascii'), llave_origen.stdout)
        self.assertIn('CARTA_VOLUME_NAME=' + self.volumen, restaurado.stdout)

        referencias = self.temporal / 'referencias.tsv'
        referencias.write_text('%s|%s|%s|%s\n' % (ORG_ID, DOMAIN_ID, nombre, hashlib.sha256(PDF).hexdigest()),
                               encoding='ascii')
        imagen = subprocess.run(['docker', 'inspect', '--format', '{{.Config.Image}}', CONTENEDOR_CARTAS],
                                check=True, capture_output=True, text=True, encoding='utf-8').stdout.strip()
        verificada = correr([
            'docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'python',
            '-v', self.volumen + ':/cartas:ro',
            '-v', str(llave_restaurada) + ':/run/carta.key:ro',
            '-v', str(referencias) + ':/run/referencias.tsv:ro',
            '-v', str(RESPALDO / 'verificar_cartas.py') + ':/run/verificar_cartas.py:ro',
            imagen, '/run/verificar_cartas.py', '/run/carta.key', '/run/referencias.tsv', '/cartas',
        ])
        self.assertEqual(verificada.returncode, 0, verificada.stderr)
        self.assertIn('1 cartas referenciadas verificadas', verificada.stdout)

        self.assertEqual(self._conteos(self.db), antes)


if __name__ == '__main__':
    unittest.main()

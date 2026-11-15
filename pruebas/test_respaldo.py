"""Pruebas del respaldo de la base (#115, RC-233): db/respaldo/respaldar.sh, restaurar.sh y comparar.sh.

Sacan un respaldo cifrado con age de la base `cirdan` del compose de prueba, lo restauran en una base nueva y
comparan filas por tabla, RLS, FORCE y políticas. También revisan la retención, que la restauración nunca toque
`cirdan` ni una base que ya existe y que una configuración mala no deje nada. No suben nada a Azure (SUBIR=0).

    python -m unittest -v pruebas/test_respaldo.py

Necesitan bash, age y age-keygen, y el contenedor de la base del compose de prueba (`cirdan-pg16` en el CI, otro
con RESPALDO_CONTENEDOR). Solo crean y borran bases que empiezan con `cirdan_prueba_respaldo_`. En el CI fallan
si falta age, para que no se salten sin aviso.
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
RESPALDO = RAIZ / 'db' / 'respaldo'
CONTENEDOR = os.environ.get('RESPALDO_CONTENEDOR', 'cirdan-pg16')
PATRON = re.compile(r'^cirdan_[0-9]{8}T[0-9]{6}Z\.dump\.age$')
HERRAMIENTAS = ('bash', 'age', 'age-keygen', 'docker')
FALTAN = [h for h in HERRAMIENTAS if not shutil.which(h)]


def correr(args, entrada=None, env=None):
    return subprocess.run(args, input=entrada, capture_output=True, text=True, encoding='utf-8',
                          env={**os.environ, **(env or {})})


def psql(sql, base='postgres'):
    proc = subprocess.run(
        ['docker', 'exec', '-i', '-e', 'BASE=' + base, CONTENEDOR, 'sh', '-c',
         'exec psql -U "$POSTGRES_USER" -d "$BASE" -X -q -At -v ON_ERROR_STOP=1'],
        input=sql, capture_output=True, text=True, encoding='utf-8')
    if proc.returncode != 0:
        raise AssertionError(proc.stderr)
    return proc.stdout.strip()


def conteos(base):
    return psql((RESPALDO / 'conteos.sql').read_text(encoding='utf-8'), base)


@unittest.skipIf(FALTAN and not os.environ.get('CI'), 'faltan %s' % ', '.join(FALTAN))
class Respaldo(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if FALTAN:
            raise AssertionError('en el CI no puede faltar: %s' % ', '.join(FALTAN))
        cls.tmp = Path(tempfile.mkdtemp(prefix='respaldo_'))
        cls.llave = cls.tmp / 'llave.txt'
        subprocess.run(['age-keygen', '-o', str(cls.llave)], check=True, capture_output=True)
        cls.publica = correr(['age-keygen', '-y', str(cls.llave)]).stdout.strip()
        cls.cirdan_antes = conteos('cirdan')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        for b in psql("SELECT datname FROM pg_database WHERE datname LIKE 'cirdan\\_prueba\\_respaldo\\_%';").split():
            psql('DROP DATABASE "%s";' % b)

    def conf(self, carpeta, **extra):
        valores = {'CONTENEDOR_BASE': CONTENEDOR, 'CARPETA': carpeta.as_posix(), 'RECEPTOR_AGE': self.publica,
                   'SUBIR': '0', 'RETENCION': '7', **extra}
        ruta = carpeta.parent / ('%s.conf' % carpeta.name)
        ruta.write_text(''.join('%s=%s\n' % kv for kv in valores.items()), encoding='utf-8')
        return ruta

    def respaldar(self, carpeta, **extra):
        return correr(['bash', str(RESPALDO / 'respaldar.sh')],
                      env={'RESPALDO_CONF': str(self.conf(carpeta, **extra))})

    def restaurar(self, archivo, base):
        return correr(['bash', str(RESPALDO / 'restaurar.sh'), str(archivo), CONTENEDOR, base],
                      env={'AGE_IDENTIDAD': str(self.llave)})

    def respaldos(self, carpeta):
        return sorted(p.name for p in carpeta.iterdir() if PATRON.match(p.name))

    def test_1_respaldo_cifrado_y_restauracion_completa(self):
        carpeta = self.tmp / 'r1'
        p = self.respaldar(carpeta)
        self.assertEqual(p.returncode, 0, p.stderr)
        nombres = self.respaldos(carpeta)
        self.assertEqual(len(nombres), 1, nombres)
        archivo = carpeta / nombres[0]
        self.assertEqual(stat.S_IMODE(archivo.stat().st_mode), 0o600)
        cabeza = archivo.read_bytes()[:64]
        self.assertTrue(cabeza.startswith(b'age-encryption.org/v1'), 'el respaldo no va cifrado con age')
        self.assertNotIn(b'PGDMP', archivo.read_bytes(), 'el respaldo deja ver el pg_dump sin cifrar')
        self.assertEqual([x.name for x in carpeta.iterdir() if x.name.endswith('.parcial')], [])

        base = 'cirdan_prueba_respaldo_%d' % os.getpid()
        r = self.restaurar(archivo, base)
        self.assertEqual(r.returncode, 0, r.stderr)
        restaurada = conteos(base)
        self.assertEqual(restaurada, conteos('cirdan'))
        filas = [linea.split('|') for linea in restaurada.splitlines()]
        self.assertGreater(sum(int(f[1]) for f in filas), 0, 'la base restaurada no tiene filas')
        con_rls = [f for f in filas if f[2] == 't']
        self.assertTrue(con_rls, 'ninguna tabla restaurada tiene RLS')
        for f in con_rls:
            self.assertEqual((f[3], f[4] != '0'), ('t', True), 'tabla con RLS sin FORCE o sin política: %s' % f[0])
        c = correr(['bash', str(RESPALDO / 'comparar.sh'), CONTENEDOR, 'cirdan', base])
        self.assertEqual(c.returncode, 0, c.stderr)
        self.assertIn('iguales', c.stdout)

    def test_2_retencion_solo_borra_respaldos_viejos(self):
        carpeta = self.tmp / 'r2'
        carpeta.mkdir(mode=0o700)
        viejos = ['cirdan_2020010%dT000000Z.dump.age' % d for d in range(1, 6)]
        ajenos = ['otro.txt', 'cirdan_x.dump.age', 'cirdan_20200101T000000Z.dump.age.bak']
        for n in viejos + ajenos:
            (carpeta / n).write_bytes(b'x')
        (carpeta / 'sub').mkdir()
        (carpeta / 'sub' / viejos[0]).write_bytes(b'x')
        p = self.respaldar(carpeta, RETENCION='3')
        self.assertEqual(p.returncode, 0, p.stderr)
        quedan = self.respaldos(carpeta)
        self.assertEqual(len(quedan), 3, quedan)
        self.assertEqual(quedan[:2], viejos[-2:])
        self.assertFalse(quedan[2].startswith('cirdan_2020'))
        for n in ajenos:
            self.assertTrue((carpeta / n).exists(), n)
        self.assertTrue((carpeta / 'sub' / viejos[0]).exists())

    def test_3_restauracion_nunca_pisa_una_base(self):
        carpeta = self.tmp / 'r3'
        self.assertEqual(self.respaldar(carpeta).returncode, 0)
        archivo = carpeta / self.respaldos(carpeta)[0]
        for base in ('cirdan', 'postgres', 'template1', 'Cirdan', 'cirdan;drop', ''):
            r = self.restaurar(archivo, base)
            self.assertNotEqual(r.returncode, 0, base)
        base = 'cirdan_prueba_respaldo_%d_b' % os.getpid()
        self.assertEqual(self.restaurar(archivo, base).returncode, 0)
        psql("CREATE TABLE marca_prueba (x int); INSERT INTO marca_prueba VALUES (1);", base)
        r = self.restaurar(archivo, base)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('ya existe', r.stderr)
        self.assertEqual(psql('SELECT count(*) FROM marca_prueba;', base), '1')
        self.assertEqual(conteos('cirdan'), self.cirdan_antes)

    def test_4_configuracion_mala_no_deja_nada(self):
        casos = [{'RECEPTOR_AGE': 'age1nooo'}, {'CLAVE_RARA': 'x'}, {'RETENCION': '0'}, {'SUBIR': '1'},
                 {'SUBIR': '1', 'CUENTA_BLOB': 'Mala_Cuenta'}, {'CONTENEDOR_BASE': '-x'}]
        for i, extra in enumerate(casos):
            carpeta = self.tmp / ('r4_%d' % i)
            p = self.respaldar(carpeta, **extra)
            self.assertNotEqual(p.returncode, 0, extra)
            self.assertFalse(carpeta.exists() and self.respaldos(carpeta), extra)

    def test_5_contenedor_sin_base_no_deja_respaldo(self):
        carpeta = self.tmp / 'r5'
        p = self.respaldar(carpeta, CONTENEDOR_BASE='no-existe-respaldo')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.respaldos(carpeta) if carpeta.exists() else [], [])
        if carpeta.exists():
            self.assertEqual([x.name for x in carpeta.iterdir() if x.name.endswith('.parcial')], [])


if __name__ == '__main__':
    unittest.main()

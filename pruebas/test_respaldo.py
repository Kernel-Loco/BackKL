"""Pruebas de respaldos (#115, RC-233, RC-28 y RC-339): base, paquete completo y restauración segura.

Sacan un respaldo cifrado con age de la base `cirdan` del compose de prueba, lo restauran en una base nueva y
comparan filas por tabla, RLS, FORCE, políticas y los permisos de PUBLIC sobre la base. También revisan la
retención por días, que la restauración nunca toque `cirdan` ni una base que ya existe, que no cree la base si no
puede descifrar, que no muestre la llave y que una configuración mala no deje nada. No suben nada a Azure: test_8 sube a un Azure falso en 127.0.0.1.

    python -m unittest -v pruebas/test_respaldo.py

Necesitan bash, age y age-keygen, y el contenedor de la base del compose de prueba: `cirdan-pg16` en el CI y, en una
PC, el de una pila aislada con RESPALDO_CONTENEDOR. Sin esa variable fuera del CI se saltan, para no tocar la base de
desarrollo. Solo crean y borran bases que empiezan con `cirdan_prueba_respaldo_<pid>_`. En el CI
fallan si falta age, para que no se salten sin aviso.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
RESPALDO = RAIZ / 'db' / 'respaldo'

def en_ci(env):
    """GitHub Actions pone CI=true. CI=false o CI=0 en una terminal no cuentan."""
    return (env.get('CI') or '').strip().lower() in ('true', '1')


def contenedor(env):
    """La base contra la que corren. En el CI el compose de prueba se llama cirdan-pg16, pero en una PC ese nombre es
    la base de desarrollo: ahí hay que nombrar el contenedor de una pila aislada con RESPALDO_CONTENEDOR."""
    return (env.get('RESPALDO_CONTENEDOR') or '').strip() or ('cirdan-pg16' if en_ci(env) else None)


CONTENEDOR = contenedor(os.environ)
CONTENEDOR_CARTAS = (os.environ.get('RESPALDO_CARTAS_CONTENEDOR') or '').strip() or (
    'cirdan-api' if en_ci(os.environ) else None)
PATRON = re.compile(r'^cirdan_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}\.(?:backup|dump)\.age$')
PREFIJO = 'cirdan_prueba_respaldo_%d_' % os.getpid()
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


def esquema(texto):
    """conteos sin las filas: tablas, RLS, FORCE, políticas y permisos de la base, que la API no cambia."""
    salida = []
    for linea in texto.splitlines():
        partes = linea.split('|')
        salida.append(linea if linea.startswith('~') else '|'.join(partes[:1] + partes[2:]))
    return salida


def existe(base):
    return psql("SELECT count(*) FROM pg_database WHERE datname = '%s';" % base) == '1'


class Contenedor(unittest.TestCase):

    def test_fuera_del_ci_no_toma_la_base_de_desarrollo(self):
        self.assertIsNone(contenedor({}))
        self.assertIsNone(contenedor({'RESPALDO_CONTENEDOR': '  '}))
        self.assertEqual(contenedor({'RESPALDO_CONTENEDOR': 'lote14-x-pg16'}), 'lote14-x-pg16')
        self.assertEqual(contenedor({'CI': 'true'}), 'cirdan-pg16')
        for valor in ('false', '0', '', 'no'):
            self.assertIsNone(contenedor({'CI': valor}), valor)
        self.assertEqual(contenedor({'CI': 'true', 'RESPALDO_CONTENEDOR': 'otra-pg16'}), 'otra-pg16')


@unittest.skipIf(FALTAN and not en_ci(os.environ), 'faltan %s' % ', '.join(FALTAN))
@unittest.skipIf(not CONTENEDOR, 'sin RESPALDO_CONTENEDOR: fuera del CI se nombra la base de una pila aislada')
@unittest.skipIf(not CONTENEDOR_CARTAS, 'sin RESPALDO_CARTAS_CONTENEDOR: nombra la API de una pila aislada')
class Respaldo(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if FALTAN:
            raise AssertionError('en el CI no puede faltar: %s' % ', '.join(FALTAN))
        cls.tmp = Path(tempfile.mkdtemp(prefix='respaldo_'))
        cls.llave = cls.tmp / 'llave.txt'
        subprocess.run(['age-keygen', '-o', str(cls.llave)], check=True, capture_output=True)
        cls.publica = correr(['age-keygen', '-y', str(cls.llave)]).stdout.strip()
        cls.otra_llave = cls.tmp / 'otra.txt'
        subprocess.run(['age-keygen', '-o', str(cls.otra_llave)], check=True, capture_output=True)
        cls.cirdan_antes = conteos('cirdan')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        # Solo las de esta corrida: otra corrida en paralelo lleva otro pid.
        patron = PREFIJO.replace('_', '\\_') + '%'
        for b in psql("SELECT datname FROM pg_database WHERE datname LIKE '%s';" % patron).split():
            psql('DROP DATABASE "%s";' % b)

    def conf(self, carpeta, **extra):
        valores = {'CONTENEDOR_BASE': CONTENEDOR, 'CONTENEDOR_CARTAS': CONTENEDOR_CARTAS,
                   'CARPETA': carpeta.as_posix(), 'RECEPTOR_AGE': self.publica,
                   'SUBIR': '0', 'RETENCION': '7', **extra}
        ruta = carpeta.parent / ('%s.conf' % carpeta.name)
        ruta.write_text(''.join('%s=%s\n' % kv for kv in valores.items()), encoding='utf-8')
        ruta.chmod(0o600)
        return ruta

    def respaldar(self, carpeta, conf=None, **extra):
        return correr(['bash', str(RESPALDO / 'respaldar.sh')],
                      env={'RESPALDO_CONF': str(conf or self.conf(carpeta, **extra))})

    def restaurar(self, archivo, base, identidad=None, entrada=None):
        return correr(['bash', str(RESPALDO / 'restaurar.sh'), str(archivo), CONTENEDOR, base],
                      entrada=entrada, env={'AGE_IDENTIDAD': identidad or str(self.llave)})

    def respaldos(self, carpeta):
        return sorted(p.name for p in carpeta.iterdir() if PATRON.match(p.name))

    def test_1_respaldo_cifrado_y_restauracion_completa(self):
        carpeta = self.tmp / 'r1'
        antes = conteos('cirdan')
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

        base = PREFIJO + 'a'
        r = self.restaurar(archivo, base)
        self.assertEqual(r.returncode, 0, r.stderr)
        restaurada = conteos(base)
        # Contra la cirdan de justo antes del respaldo o la de ahora: un hilo de la API puede escribir en medio.
        self.assertIn(restaurada, (antes, conteos('cirdan')))
        # La 004 le quita TEMPORARY a PUBLIC, pg_dump no lo guarda y restaurar.sh lo vuelve a quitar.
        self.assertIn('~base|public|CONNECT', restaurada.splitlines())
        filas = [linea.split('|') for linea in restaurada.splitlines() if not linea.startswith('~')]
        self.assertGreater(sum(int(f[1]) for f in filas), 0, 'la base restaurada no tiene filas')
        con_rls = [f for f in filas if f[2] == 't']
        self.assertTrue(con_rls, 'ninguna tabla restaurada tiene RLS')
        for f in con_rls:
            self.assertEqual((f[3], f[4] != '0'), ('t', True), 'tabla con RLS sin FORCE o sin política: %s' % f[0])
        c = correr(['bash', str(RESPALDO / 'comparar.sh'), CONTENEDOR, 'cirdan', base])
        self.assertEqual(c.returncode, 0, c.stderr)
        self.assertIn('iguales', c.stdout)

    def test_2_retencion_por_dias_solo_borra_respaldos_viejos(self):
        carpeta = self.tmp / 'r2'
        carpeta.mkdir(mode=0o700)
        viejos = ['cirdan_2020010%dT000000Z_0000000%d.dump.age' % (d, d) for d in range(1, 6)]
        # Una corrida a mano el mismo día que el último viejo: no le quita su lugar a otro día.
        mismo_dia = 'cirdan_20200105T120000Z_abcdef01.dump.age'
        ajenos = ['otro.txt', 'cirdan_x.dump.age', 'cirdan_20200101T000000Z.dump.age',
                  'cirdan_20200101T000000Z_00000001.dump.age.bak']
        for n in viejos + [mismo_dia] + ajenos:
            (carpeta / n).write_bytes(b'x')
        (carpeta / 'sub').mkdir()
        (carpeta / 'sub' / viejos[0]).write_bytes(b'x')
        p = self.respaldar(carpeta, RETENCION='3')
        self.assertEqual(p.returncode, 0, p.stderr)
        quedan = self.respaldos(carpeta)
        # Los 3 días más recientes con respaldo: hoy, el 5 (con sus 2 archivos) y el 4.
        self.assertEqual(len(quedan), 4, quedan)
        self.assertEqual(quedan[:3], sorted([viejos[3], viejos[4], mismo_dia]), quedan)
        self.assertFalse(quedan[3].startswith('cirdan_2020'))
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
        # Con otra llave o un archivo cortado no se crea la base, así que el reintento con el mismo nombre sirve.
        base = PREFIJO + 'b'
        r = self.restaurar(archivo, base, identidad=str(self.otra_llave))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(existe(base), 'quedó una base vacía con la llave equivocada')
        cortado = self.tmp / 'cortado.dump.age'
        cortado.write_bytes(archivo.read_bytes()[:-200])
        r = self.restaurar(cortado, base)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(existe(base), 'quedó una base vacía con un respaldo cortado')
        self.assertEqual(self.restaurar(archivo, base).returncode, 0)
        psql("CREATE TABLE marca_prueba (x int); INSERT INTO marca_prueba VALUES (1);", base)
        r = self.restaurar(archivo, base)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('ya existe', r.stderr)
        self.assertEqual(psql('SELECT count(*) FROM marca_prueba;', base), '1')
        # Sin las filas, que la API puede cambiar mientras corre la prueba.
        self.assertEqual(esquema(conteos('cirdan')), esquema(self.cirdan_antes))

    def test_4_configuracion_mala_no_deja_nada(self):
        casos = [{'RECEPTOR_AGE': 'age1nooo'}, {'CLAVE_RARA': 'x'}, {'RETENCION': '0'},
                 {'CONTENEDOR_CARTAS': '-invalido'}, {'SUBIR': '1'},
                 {'SUBIR': '1', 'CUENTA_BLOB': 'Mala_Cuenta'}, {'CONTENEDOR_BASE': '-x'},
                 {'CARPETA': '/tmp/con espacio'}, {'CARPETA': '/tmp/../etc'}]
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

    def test_6_la_llave_nunca_sale_en_pantalla(self):
        carpeta = self.tmp / 'r6'
        self.assertEqual(self.respaldar(carpeta).returncode, 0)
        archivo = carpeta / self.respaldos(carpeta)[0]
        texto = self.llave.read_text(encoding='utf-8')
        secreto = [x for x in texto.splitlines() if x.startswith('AGE-SECRET-KEY-')][0]
        for identidad in (secreto, 'x' + secreto, str(self.tmp / 'no_existe.txt')):
            r = self.restaurar(archivo, PREFIJO + 'c', identidad=identidad)
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn('AGE-SECRET-KEY', r.stdout + r.stderr)
        self.assertFalse(existe(PREFIJO + 'c'))
        # Con AGE_IDENTIDAD=- la llave llega por stdin, como la manda restaurar_respaldo.ps1.
        r = self.restaurar(archivo, PREFIJO + 'd', identidad='-', entrada=texto)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('AGE-SECRET-KEY', r.stdout + r.stderr)
        self.assertIn('~base|public|CONNECT', conteos(PREFIJO + 'd').splitlines())

    def test_7_configuracion_que_otros_pueden_cambiar(self):
        carpeta = self.tmp / 'r7'
        conf = self.conf(carpeta)
        conf.chmod(0o666)
        p = self.respaldar(carpeta, conf=conf)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('escritura', p.stderr)
        conf.chmod(0o600)
        enlace = self.tmp / 'r7_enlace.conf'
        enlace.symlink_to(conf)
        p = self.respaldar(carpeta, conf=enlace)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('enlace', p.stderr)
        self.assertFalse(carpeta.exists() and self.respaldos(carpeta))
        # CARPETA con / al final se normaliza: un enlace a una carpeta con / al final no pasa por carpeta.
        real = self.tmp / 'r7_real'
        real.mkdir(mode=0o700)
        ln = self.tmp / 'r7_ln'
        ln.symlink_to(real)
        p = self.respaldar(ln, CARPETA=ln.as_posix() + '/')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.respaldos(real), [])
        bien = self.tmp / 'r7_bien'
        p = self.respaldar(bien, CARPETA=bien.as_posix() + '//')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.respaldos(bien)), 1)

    def test_8_subida_que_choca_con_su_propio_blob(self):
        # Contra un Azure falso en 127.0.0.1, con una copia del script que apunta ahí por http. Como el rol de la VM
        # (blobs/add/action, sin blobs/write), un PUT sobre un blob que ya está responde 403, no 409.
        falso = AzureFalso()
        try:
            texto = (RESPALDO / 'respaldar.sh').read_text(encoding='utf-8')
            cambios = (('https://$CUENTA_BLOB.blob.core.windows.net', falso.url, 1),
                       ("--proto '=https' --tlsv1.2", "--proto '=http'", 2),
                       ('http://169.254.169.254', falso.url, 1))
            for viejo, nuevo, veces in cambios:
                self.assertEqual(texto.count(viejo), veces, viejo)
                texto = texto.replace(viejo, nuevo)
            script = self.tmp / 'respaldar_falso.sh'
            script.write_text(texto, encoding='utf-8')

            def subir(caso, modo, rol=True):
                falso.blobs.clear()
                falso.modo, falso.rol, falso.puts = modo, rol, 0
                carpeta = self.tmp / ('r8_' + caso)
                p = correr(['bash', str(script)], env={
                    'RESPALDO_CONF': str(self.conf(carpeta, SUBIR='1', CUENTA_BLOB='falsa',
                                                   CONTENEDOR_BLOB='respaldos')),
                    'NO_PROXY': '127.0.0.1', 'no_proxy': '127.0.0.1'})
                return p, self.respaldos(carpeta)

            # El primer PUT llega pero su respuesta se pierde (503), curl lo reintenta y Azure da 403: vale, porque
            # el blob que quedó es este mismo archivo.
            p, locales = subir('reintento', 'perder')
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn('respaldo: subido a falsa/respaldos/' + locales[0], p.stdout)
            self.assertEqual(sorted(falso.blobs), locales)
            self.assertGreaterEqual(falso.puts, 2, 'curl no reintentó el PUT')
            # Si lo que quedó en Azure es otro archivo, no se da por subido.
            p, locales = subir('distinto', 'perder_distinto')
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('en Azure hay otro blob ' + locales[0], p.stderr)
            self.assertNotIn('respaldo: subido', p.stdout)
            # Sin el rol de crear blobs el 403 sigue siendo error, con su pista, y el respaldo local se queda.
            p, locales = subir('sin_rol', 'normal', rol=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('respondió 403 al subir %s (falta el rol' % locales[0], p.stderr)
            self.assertEqual((falso.blobs, len(locales)), ({}, 1))
        finally:
            falso.cerrar()


class AzureFalso:
    """Token de IMDS, HEAD y PUT de blobs. modo 'perder': el primer PUT guarda el blob y responde 503.
    'perder_distinto': igual, pero guarda otro contenido. rol=False: todo PUT responde 403."""

    def __init__(self):
        falso = self
        self.blobs, self.modo, self.rol, self.puts = {}, 'normal', True, 0

        class Manejador(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def responder(self, codigo, cuerpo=b'', cabeceras=()):
                self.send_response(codigo)
                for k, v in cabeceras:
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)

            def do_GET(self):
                if self.path.startswith('/metadata/identity/oauth2/token'):
                    self.responder(200, json.dumps({'access_token': 'tok'}).encode())
                else:
                    self.responder(404)

            def do_HEAD(self):
                n = self.path.rsplit('/', 1)[-1]
                if n in falso.blobs:
                    self.send_response(200)
                    self.send_header('Content-MD5', falso.blobs[n])
                else:
                    self.send_response(404)
                self.end_headers()

            def do_PUT(self):
                falso.puts += 1
                n = self.path.rsplit('/', 1)[-1]
                if self.headers.get('Expect', '').lower() == '100-continue':
                    self.send_response_only(100)
                    self.end_headers()
                datos = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                md5 = base64.b64encode(hashlib.md5(datos).digest()).decode()
                if self.headers.get('Authorization') != 'Bearer tok' or not falso.rol:
                    self.responder(403)
                elif n in falso.blobs:
                    self.responder(403, cabeceras=(('x-ms-error-code', 'UnauthorizedBlobOverwrite'),))
                elif md5 != self.headers.get('Content-MD5'):
                    self.responder(400)
                elif falso.modo.startswith('perder'):
                    falso.blobs[n] = md5 if falso.modo == 'perder' else 'otro' + md5
                    falso.modo = 'normal'
                    self.responder(503)
                else:
                    falso.blobs[n] = md5
                    self.responder(201)

        self.servidor = ThreadingHTTPServer(('127.0.0.1', 0), Manejador)
        self.url = 'http://127.0.0.1:%d' % self.servidor.server_address[1]
        threading.Thread(target=self.servidor.serve_forever, daemon=True).start()

    def cerrar(self):
        self.servidor.shutdown()
        self.servidor.server_close()


if __name__ == '__main__':
    unittest.main()

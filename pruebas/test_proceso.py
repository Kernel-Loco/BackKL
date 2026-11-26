"""RC-324: un hijo lanzado como lo lanza github._ejecutar no lee el entorno de la API ni del programador.

Corre en Linux, dentro de la imagen (paso 'Pruebas dentro del contenedor' del CI). En cada caso un proceso de Python
nuevo, con una variable CIRDAN_FAKE_ en su entorno como la contraseña de la base, lanza `cat /proc/<su pid>/environ`
con github._ejecutar y github._entorno. Sin no_volcable() el hijo la lee (la prueba sí detecta el hueco). Con
no_volcable(), como en el arranque de la API y del programador, ya no. Nunca imprime el valor.

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest pruebas/test_proceso.py
"""
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]

SONDA = textwrap.dedent('''
    import os, sys, tempfile
    from cirdan.recolectores import github
    from cirdan.proceso import no_volcable
    if sys.argv[1] == 'si':
        assert no_volcable() is True
    casa = tempfile.mkdtemp()
    salida = os.path.join(casa, 'salida')
    res = github._ejecutar(['cat', '/proc/%d/environ' % os.getpid()], 10, github._entorno(casa), casa, salida=salida)
    with open(salida, 'rb') as f:
        datos = f.read()
    print('rc=%d leyo=%s' % (res.returncode, os.environ['CIRDAN_FAKE_ENTORNO'].encode() in datos))
''')


@unittest.skipUnless(sys.platform.startswith('linux'), '/proc y prctl solo existen en Linux: corre en la imagen')
class EntornoDeLosHijos(unittest.TestCase):
    def sonda(self, endurecido):
        env = dict(os.environ, CIRDAN_FAKE_ENTORNO='CIRDAN_FAKE_' + secrets.token_hex(16), PYTHONPATH=str(RAIZ))
        r = subprocess.run([sys.executable, '-c', SONDA, 'si' if endurecido else 'no'], env=env, cwd=RAIZ,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        return r.stdout.strip()

    def test_1_sin_no_volcable_el_hijo_lee_el_entorno_del_padre(self):
        """El control: con el mismo uid y sin endurecer, cat lee /proc/<padre>/environ. Si esto deja de pasar, la
        prueba 2 ya no prueba nada."""
        self.assertEqual(self.sonda(False), 'rc=0 leyo=True')

    def test_2_con_no_volcable_el_hijo_ya_no_lo_lee(self):
        """Con prctl(PR_SET_DUMPABLE, 0) /proc/<padre>/environ es de root: cat falla y no ve la variable."""
        salida = self.sonda(True)
        self.assertTrue(salida.endswith('leyo=False'), salida)
        self.assertNotEqual(salida, 'rc=0 leyo=False', 'cat no debería poder abrir el archivo')

    def init(self, *comando, **kw):
        env = dict(os.environ, CIRDAN_FAKE_ENTORNO='CIRDAN_FAKE_' + secrets.token_hex(16), PYTHONPATH=str(RAIZ))
        return subprocess.Popen([sys.executable, '-m', 'cirdan.init', *comando], env=env, cwd=RAIZ,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw)

    def test_4_un_hijo_del_init_no_lee_el_entorno_del_init(self):
        """El PID 1 de la imagen guarda todo el entorno: un hijo suyo, que sí es volcable, no lo lee en /proc."""
        hijo = SONDA.replace("'/proc/%d/environ' % os.getpid()", "'/proc/%d/environ' % os.getppid()")
        p = self.init(sys.executable, '-c', hijo, 'no')
        salida, error = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 0, error[-400:])
        self.assertTrue(salida.strip().endswith('leyo=False'), salida)
        self.assertNotEqual(salida.strip(), 'rc=0 leyo=False', 'cat no debería poder abrir el archivo')

    def test_5_pasa_el_codigo_de_salida_y_las_senales(self):
        p = self.init(sys.executable, '-c', 'raise SystemExit(7)')
        p.communicate(timeout=60)
        self.assertEqual(p.returncode, 7)
        p = self.init(sys.executable, '-c', 'import sys, time; print("listo", flush=True); time.sleep(60)')
        self.assertEqual(p.stdout.readline().strip(), 'listo')
        p.send_signal(signal.SIGTERM)
        p.communicate(timeout=30)
        self.assertEqual(p.returncode, 128 + signal.SIGTERM)

    def test_6_recoge_a_los_huerfanos(self):
        """Un sleep que queda huérfano le llega al init y no se queda zombi (lo que hacía tini con los git)."""
        guion = ('(sleep 0.2 & echo $! > "$1") ; sleep 1.5; '
                 'if [ -e /proc/$(cat "$1") ]; then grep State /proc/$(cat "$1")/status; else echo recogido; fi')
        with tempfile.TemporaryDirectory() as d:
            p = self.init('sh', '-c', guion, 'sh', os.path.join(d, 'pid'))
            salida, error = p.communicate(timeout=60)
        self.assertEqual((p.returncode, salida.strip()), (0, 'recogido'), error[-400:])

    def test_3_la_api_y_el_programador_lo_llaman_al_arrancar(self):
        """no_volcable() está en el arranque de los dos procesos que corren git y gitleaks con secretos."""
        api = (RAIZ / 'cirdan/api/main.py').read_text(encoding='utf-8')
        prog = (RAIZ / 'cirdan/programador/__main__.py').read_text(encoding='utf-8')
        arranque = api.split('async def _arranque(app):', 1)[1].split('yield', 1)[0]
        self.assertIn('no_volcable()', arranque)
        self.assertIn('no_volcable()', prog.split('def main(argv=None):', 1)[1].split('while not parada', 1)[0])
        imagen = (RAIZ / 'Dockerfile').read_text(encoding='utf-8')
        self.assertIn('ENTRYPOINT ["python", "-m", "cirdan.init"]', imagen)


if __name__ == '__main__':
    unittest.main()

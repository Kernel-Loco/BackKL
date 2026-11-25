"""Usuarios de Valkey (RC-292): la API entra como cirdan_api, solo con sus comandos y sus prefijos de llave.

Lista corre sin base ni red: compara lo que usa cirdan/auth/sessions.py (sus llamadas y los redis.call de sus EVAL) con
la lista de cirdan_api del command de docker-compose.yml, para que un comando o un prefijo nuevo no rompa en la VM.
EnVivo corre contra el Valkey de la pila desechable, con docker exec: CONFIG GET, MODULE LIST y lo demás dan NOPERM con
cirdan_api, default no entra y la contraseña de cirdan_admin no llega a la API.
"""
import os
import re
import subprocess
import unittest
from pathlib import Path

from pruebas.pila import exigir_desechable

RAIZ = Path(__file__).resolve().parents[1]
VALKEY = os.environ.get('CIRDAN_TEST_VALKEY', 'cirdan-valkey')
API = os.environ.get('CIRDAN_TEST_API_CONTAINER', 'cirdan-api')
# Comandos que la API nunca debe poder correr.
PROHIBIDOS = {'config', 'module', 'flushall', 'flushdb', 'keys', 'scan', 'debug', 'acl', 'shutdown', 'save', 'bgsave',
              'replicaof', 'slaveof', 'monitor', 'script', 'function', 'publish', 'subscribe', 'migrate', 'restore'}
# Llamadas de redis-py en sessions.py y el comando de Valkey que mandan.
METODOS = {'get': {'get'}, 'set': {'set'}, 'mget': {'mget'}, 'getdel': {'getdel'}, 'delete': {'del'},
           'expire': {'expire'}, 'eval': {'eval'}, 'incr': {'incrby'}, 'sadd': {'sadd'}, 'pipeline': {'multi', 'exec'},
           'execute': set()}


def _usuario(nombre):
    """Las palabras del command de Valkey que siguen a `--user <nombre>`, hasta el siguiente --user o --save."""
    texto = (RAIZ / 'docker-compose.yml').read_text(encoding='utf-8')
    bloque = texto.split('\n  valkey:\n', 1)[1].split('\n  api:\n', 1)[0]
    palabras = [m.strip().strip('"') for m in re.findall(r'^\s+- (.+)$', bloque.split('ports:', 1)[0], re.M)]
    inicio = palabras.index(nombre, palabras.index('--user')) + 1
    fin = next(i for i in range(inicio, len(palabras)) if palabras[i] in ('--user', '--save'))
    return palabras[inicio:fin]


class Lista(unittest.TestCase):
    def setUp(self):
        self.api = _usuario('cirdan_api')
        self.permitidos = {p[1:].lower() for p in self.api if p.startswith('+')}
        self.prefijos = {p[1:-1] for p in self.api if p.startswith('~')}
        self.codigo = (RAIZ / 'cirdan' / 'auth' / 'sessions.py').read_text(encoding='utf-8')

    def test_1_cirdan_api_empieza_sin_nada_y_sin_pubsub(self):
        self.assertEqual(self.api[:2], ['reset', 'on'])
        self.assertTrue(self.api[2].startswith('>${VALKEY_PASSWORD:?'))
        self.assertIn('resetchannels', self.api)
        self.assertNotIn('&*', self.api)
        self.assertNotIn('~*', self.api)
        # -@all antes de los +: lo que no está en la lista no entra.
        self.assertLess(self.api.index('-@all'), min(i for i, p in enumerate(self.api) if p.startswith('+')))
        self.assertFalse([p for p in self.api if p.startswith('+@')], 'sin categorías enteras')
        self.assertFalse({c.split('|')[0] for c in self.permitidos} & PROHIBIDOS)

    def test_2_default_apagado_y_admin_con_otra_contrasena(self):
        self.assertEqual(_usuario('default'), ['off'])
        admin = _usuario('cirdan_admin')
        self.assertIn('>${VALKEY_ADMIN_PASSWORD:?Falta VALKEY_ADMIN_PASSWORD en .env}', admin)
        self.assertNotIn('--requirepass', (RAIZ / 'docker-compose.yml').read_text(encoding='utf-8'))

    def test_3_cada_comando_de_sessions_esta_en_la_lista(self):
        usados = {c.lower() for c in re.findall(r"redis\.call\('(\w+)'", self.codigo)}
        for metodo in re.findall(r'(?:_valkey\(\)|\bpipe)\.(\w+)\(', self.codigo):
            self.assertIn(metodo, METODOS, 'llamada nueva de redis-py en sessions.py: súmala a METODOS y al compose')
            usados |= METODOS[metodo]
        self.assertGreater(len(usados), 10)
        self.assertEqual(sorted(usados - self.permitidos), [],
                         'comandos que usa sessions.py y cirdan_api no tiene en docker-compose.yml')

    def test_4_cada_prefijo_de_sessions_esta_en_la_lista(self):
        literales = set(re.findall(r"['\"]([a-z][a-z-]*):", self.codigo)) - {'redis'}
        self.assertGreater(len(literales), 10)
        faltan = sorted(p for p in literales if not any(x.startswith(p + ':') or x == p + ':*' for x in self.prefijos))
        self.assertEqual(faltan, [], 'prefijos de llave de sessions.py que cirdan_api no tiene')

    def test_5_la_api_entra_como_cirdan_api_y_no_recibe_la_de_admin(self):
        texto = (RAIZ / 'docker-compose.yml').read_text(encoding='utf-8')
        api = texto.split('\n  api:\n', 1)[1].split('\n  programador:\n', 1)[0]
        self.assertIn('VALKEY_URL: redis://cirdan_api:${VALKEY_PASSWORD}@valkey:6379/0', api)
        self.assertIn("'redis://cirdan_api:%s@", self.codigo)
        for servicio in ('api', 'programador', 'demo-accounts'):
            bloque = texto.split('\n  %s:\n' % servicio, 1)[1].split('\n  ', 1)[0] if servicio != 'api' else api
            self.assertNotIn('VALKEY_ADMIN_PASSWORD', bloque, servicio)
        lineas = [n for n in texto.splitlines() if 'VALKEY_ADMIN_PASSWORD' in n]
        self.assertEqual(len(lineas), 2, 'solo en el command y el environment de valkey')


class EnVivo(unittest.TestCase):
    @staticmethod
    def cli(*args, usuario='cirdan_api', variable='VALKEY_PASSWORD'):
        exigir_desechable()
        r = subprocess.run(['docker', 'exec', VALKEY, 'sh', '-c',
                            'valkey-cli --user %s -a "$%s" --no-auth-warning "$@"' % (usuario, variable), 'sh', *args],
                           capture_output=True, text=True, timeout=30)
        return (r.stdout + r.stderr).strip()

    @staticmethod
    def sin_usuario(*args):
        exigir_desechable()
        r = subprocess.run(['docker', 'exec', VALKEY, 'sh', '-c',
                            'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning "$@"', 'sh', *args],
                           capture_output=True, text=True, timeout=30)
        return (r.stdout + r.stderr).strip()

    def test_1_cirdan_api_da_noperm_en_comandos_de_admin(self):
        for comando in (['CONFIG', 'GET', 'maxmemory'], ['MODULE', 'LIST'], ['FLUSHALL'], ['KEYS', '*'], ['SCAN', '0'],
                        ['ACL', 'LIST'], ['PUBLISH', 'canal', 'x'], ['CONFIG', 'SET', 'save', '60 1']):
            with self.subTest(comando=comando):
                self.assertIn('NOPERM', self.cli(*comando))

    def test_2_cirdan_api_solo_llega_a_sus_prefijos_tambien_dentro_de_un_eval(self):
        self.assertEqual(self.cli('PING'), 'PONG')
        self.assertEqual(self.cli('SET', 'sess:rc292-prueba', 'x', 'EX', '5'), 'OK')
        self.assertEqual(self.cli('DEL', 'sess:rc292-prueba'), '1')
        self.assertIn('NOPERM', self.cli('SET', 'rc292:fuera', 'x'))
        # KEYS sí se deja llamar desde un script (CONFIG no: daría 'not allowed from script' antes de la ACL).
        # Un comando prohibido dentro de un EVAL no da NOPERM sino 'ERR ACL failure in script: ... no permissions'.
        # Una llave ajena dentro del EVAL sí da 'NOPERM No permissions to access a key'.
        self.assertRegex(self.cli('EVAL', "return redis.call('KEYS', '*')", '0'),
                         r'^ERR ACL failure in script: User cirdan_api has no permissions')
        self.assertIn('NOPERM', self.cli('EVAL', "return redis.call('SET', KEYS[1], 'x')", '1', 'rc292:fuera'))

    def test_3_default_no_entra_ni_con_la_contrasena_de_la_api(self):
        self.assertNotIn('PONG', self.sin_usuario('PING'))
        self.assertNotIn('PONG', self.cli('PING', usuario='default'))

    def test_4_cirdan_admin_entra_y_la_api_no_tiene_su_contrasena(self):
        self.assertEqual(self.cli('ACL', 'WHOAMI', usuario='cirdan_admin', variable='VALKEY_ADMIN_PASSWORD'),
                         'cirdan_admin')
        exigir_desechable()
        r = subprocess.run(['docker', 'exec', API, 'sh', '-c', 'test -z "${VALKEY_ADMIN_PASSWORD:-}"'],
                           capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 0, 'la API no recibe VALKEY_ADMIN_PASSWORD')


if __name__ == '__main__':
    unittest.main()

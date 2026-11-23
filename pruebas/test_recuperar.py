"""Recuperar la contraseña olvidada con un enlace al correo (RC-335): el Hecho cuando, en un compose aislado y sin red.

Corre en el mismo compose que pruebas/test_enlace.py (pruebas/enlace/docker-compose.yml), en una red interna sin salida
a internet, contra una API nueva cuyo Resend es el simulado de pruebas/enlace/correo_falso.py. Nunca toca cirdan-pg16:

    C='docker compose -p backkl-enlace -f docker-compose.yml -f pruebas/enlace/docker-compose.yml'
    $C up -d --build --wait db valkey api correo-falso
    $C run --rm pruebas python -m unittest -v pruebas/test_enlace.py pruebas/test_recuperar.py | tee enlace.log
    sh pruebas/enlace/revisar_log.sh enlace.log      # los tokens tampoco están en el log de la API
    $C down -v

Fuera de ese compose (sin ENLACE_CORREO_FALSO) se salta. Cambia contraseñas de cuentas de demo en esa base desechable
y al final les devuelve su huella. alex sigue con MFA. Todas las peticiones salen de la IP del contenedor, así que cada
prueba borra los contadores de pedidos al empezar.
"""
import hashlib
import json
import os
import re
import time
import unittest
import urllib.request

from pruebas import sesion
from pruebas.sesion import Client

FALSO = os.environ.get('ENLACE_CORREO_FALSO')
AUTH = sesion.AUTH
MAYA, JORDAN, DANA, ALEX = ('maya.reed@acme-demo.mx', 'jordan.tate@acme-demo.mx', 'dana.cruz@beta-corp.mx',
                            'alex.morgan@acme-demo.mx')
OLMARDO = 'admin@olmardo.com'
NADIE = 'nadie.existe@acme-demo.mx'
CUENTAS = (MAYA, JORDAN, DANA, ALEX, OLMARDO)
ENLACE = re.compile(r'http://portal\.prueba/forgot-password/reset#t=([A-Za-z0-9_-]+)')
INVALIDO = 'El enlace no es válido o ya venció. Pide otro desde «¿Olvidaste tu contraseña?».'
NUEVA = 'Marea-Baja-Recupera-2026'
COMUN = '1qaz2wsx3edc'  # 12 caracteres y en cirdan/auth/datos/contrasenas_comunes.txt
ASUNTO_ENLACE = 'Elige una contraseña nueva para LowTide'
ASUNTO_AVISO = 'Tu contraseña de LowTide cambió'
TOKENS = []  # cada token visto, para buscarlo en audit_log y en el log de la API


def _falso(metodo, ruta, datos=None):
    req = urllib.request.Request(FALSO + ruta, method=metodo, data=json.dumps(datos).encode() if datos else None,
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read() or b'null')


def correos(para, asunto=ASUNTO_ENLACE):
    return [c for c in _falso('GET', '/correos') if c['correo']['to'] == [para] and c['correo']['subject'] == asunto]


def esperar_correos(para, cuantos, asunto=ASUNTO_ENLACE, plazo=8):
    """El envío corre después de responder: espera a que el simulado reciba `cuantos` para ese correo."""
    fin = time.time() + plazo
    while time.time() < fin:
        recibidos = correos(para, asunto)
        if len(recibidos) >= cuantos:
            return recibidos
        time.sleep(0.2)
    return correos(para, asunto)


def token_de(correo):
    token = ENLACE.search(correo['correo']['text']).group(1)
    TOKENS.append(token)
    return token


def pedir(email):
    """POST /password-reset con un captcha resuelto. Devuelve (código, cuerpo, segundos de la petición)."""
    cliente = Client()
    datos = {'email': email, 'captcha': sesion.captcha(cliente)}
    inicio = time.perf_counter()
    codigo, cuerpo = cliente.post(AUTH + '/password-reset', datos)
    return codigo, cuerpo, time.perf_counter() - inicio


def confirmar(token, password=NUEVA):
    return Client().post(AUTH + '/password-reset/confirm', {'token': token, 'new_password': password})


def entrar(email, password):
    cliente = Client()
    return cliente, sesion.post_login(cliente, email, password)


@unittest.skipUnless(FALSO, 'Corre en el compose aislado de pruebas/enlace (ENLACE_CORREO_FALSO)')
class RecuperarAislado(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        import redis
        cls.pg = psycopg.connect(host=os.environ['PGHOST'], port=os.environ.get('PGPORT', '5432'), dbname='cirdan',
                                 user=os.environ.get('POSTGRES_USER', 'postgres'),
                                 password=os.environ['POSTGRES_PASSWORD'], autocommit=True)
        cls.valkey = redis.Redis.from_url(os.environ['VALKEY_URL'], decode_responses=True)
        # La huella de cada cuenta, para devolverla al final aunque una prueba falle a la mitad.
        cls.huellas = dict(cls.pg.execute('SELECT email::text, password_hash FROM users WHERE email = ANY(%s)',
                                          (list(CUENTAS),)).fetchall())
        cls.pg.execute('UPDATE users SET mfa_enabled_at = NULL, totp_secret_enc = NULL WHERE email IN (%s, %s, %s)',
                       (MAYA, JORDAN, OLMARDO))
        # Desde cero también al repetirla sin bajar el compose: tokens, contadores de pedidos y los del día. Los del día
        # van todos: el enlace para entrar (RC-63) y el de recuperar comparten el de la cuenta (H1 de la revisión), y
        # test_enlace.py corre antes en el mismo compose.
        for patron in ('pwreset*', 'link:day:*'):
            for llave in cls.valkey.scan_iter(patron):
                cls.valkey.delete(llave)
        _falso('DELETE', '/correos')
        cls.desde = cls.pg.execute('SELECT clock_timestamp()').fetchone()[0]

    @classmethod
    def tearDownClass(cls):
        for email, huella in cls.huellas.items():
            cls.pg.execute('UPDATE users SET password_hash = %s WHERE email = %s', (huella, email))
        cls.pg.close()
        cls.valkey.close()

    def setUp(self):
        for llave in self.valkey.scan_iter('pwreset:req:*'):
            self.valkey.delete(llave)

    def bitacora(self, email, accion):
        """details del último registro de esa acción de esa cuenta, o None."""
        fila = self.pg.execute(
            'SELECT a.details FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = %s AND a.action = %s'
            ' AND a.occurred_at >= %s ORDER BY a.chain_seq DESC LIMIT 1', (email, accion, self.desde)).fetchone()
        return fila[0] if fila else None

    def token_nuevo(self, email):
        antes = len(correos(email))
        codigo, cuerpo, _ = pedir(email)
        self.assertEqual(codigo, 202, cuerpo)
        recibidos = esperar_correos(email, antes + 1)
        self.assertEqual(len(recibidos), antes + 1)
        return token_de(recibidos[-1])

    def test_1_correo_que_existe_y_que_no_dan_la_misma_respuesta(self):
        existe, nadie = pedir(MAYA), pedir(NADIE)
        self.assertEqual(existe[:2], nadie[:2])
        self.assertEqual(existe[0], 202)
        self.assertIn('30 minutos', existe[1]['detail'])
        # El trabajo corre después de responder: las dos tardan lo mismo, sin buscar la cuenta ni mandar el correo.
        self.assertLess(abs(existe[2] - nadie[2]), 0.5, (existe[2], nadie[2]))
        recibidos = esperar_correos(MAYA, 1)
        self.assertEqual(len(recibidos), 1)
        time.sleep(1)
        self.assertEqual(correos(NADIE), [])
        correo = recibidos[0]
        self.assertEqual(correo['correo']['from'], 'LowTide <acceso@lowtidesec.com>')
        token = token_de(correo)
        self.assertGreaterEqual(len(token), 43)  # 32 bytes (256 bits) en base64 url-safe
        for texto in (correo['correo']['text'], correo['correo']['html']):
            self.assertIn('30 minutos', texto)
            self.assertNotIn('Acme', texto)
            self.assertNotIn(MAYA, texto)
        self.assertEqual(self.bitacora(MAYA, 'auth.password_reset_requested'), {'expires_minutes': 30})
        # En Valkey solo va el SHA-256 del token, que vence en 30 min.
        llave = 'pwreset:' + hashlib.sha256(token.encode()).hexdigest()
        self.assertTrue(self.valkey.exists(llave))
        self.assertLessEqual(self.valkey.ttl(llave), 30 * 60)
        self.assertGreater(self.valkey.ttl(llave), 29 * 60)
        self.assertEqual([k for k in self.valkey.scan_iter('*' + token + '*')], [])

    def test_2_cambia_la_contrasena_cierra_las_sesiones_y_sirve_una_vez(self):
        abierta, (codigo, cuerpo) = entrar(JORDAN, sesion.PASSWORD)
        self.assertEqual(codigo, 200, cuerpo)
        self.assertEqual(abierta.get(AUTH + '/me')[0], 200)
        llave_fallos = 'login:fail:email:' + hashlib.sha256(JORDAN.encode()).hexdigest()
        self.valkey.set(llave_fallos, 4, ex=900)
        token = self.token_nuevo(JORDAN)
        codigo, cuerpo = confirmar(token)
        self.assertEqual(codigo, 200, cuerpo)
        self.assertEqual(cuerpo['passkeys_removed'], 0)
        self.assertEqual(abierta.get(AUTH + '/me')[0], 401)   # la sesión de antes se cerró
        self.assertEqual(confirmar(token)[0:2], (400, {'detail': INVALIDO}))   # la segunda vez
        time.sleep(0.5)
        self.assertFalse(self.valkey.exists(llave_fallos))   # los fallos de login se borraron
        self.assertEqual(entrar(JORDAN, sesion.PASSWORD)[1][0], 401)   # la anterior ya no sirve
        cliente, (codigo, cuerpo) = entrar(JORDAN, NUEVA)
        self.assertEqual(codigo, 200, cuerpo)
        self.assertFalse(cuerpo['mfa_required'])
        self.assertEqual(cliente.get(AUTH + '/me')[0], 200)
        self.assertEqual(self.bitacora(JORDAN, 'auth.password_reset'), {'passkeys_removed': 0})
        huella = self.pg.execute('SELECT password_hash FROM users WHERE email = %s', (JORDAN,)).fetchone()[0]
        self.assertTrue(huella.startswith('lt1$'), huella[:8])   # argon2id cifrada (RC-330)
        # El segundo correo avisa que la contraseña cambió, sin enlace.
        aviso = esperar_correos(JORDAN, 1, ASUNTO_AVISO)
        self.assertEqual(len(aviso), 1)
        self.assertNotIn('http', aviso[0]['correo']['text'])
        self.assertIsNone(self.bitacora(JORDAN, 'auth.password_reset_notice_failed'))

    def test_3_pedir_otro_anula_el_anterior(self):
        primero = self.token_nuevo(OLMARDO)
        segundo = self.token_nuevo(OLMARDO)
        self.assertNotEqual(primero, segundo)
        self.assertEqual(confirmar(primero), (400, {'detail': INVALIDO}))
        self.assertEqual(confirmar(segundo)[0], 200)

    def test_4_vencido_no_sirve(self):
        token = self.token_nuevo(OLMARDO)
        self.assertEqual(self.valkey.pexpire('pwreset:' + hashlib.sha256(token.encode()).hexdigest(), 1), 1)
        time.sleep(0.2)
        self.assertEqual(confirmar(token), (400, {'detail': INVALIDO}))

    def test_5_con_totp_el_siguiente_inicio_lo_pide(self):
        token = self.token_nuevo(ALEX)
        self.assertEqual(confirmar(token)[0], 200)
        fila = self.pg.execute('SELECT mfa_enabled_at IS NOT NULL AND totp_secret_enc IS NOT NULL FROM users'
                               ' WHERE email = %s', (ALEX,)).fetchone()
        self.assertTrue(fila[0])   # el MFA no se tocó
        cliente, (codigo, cuerpo) = entrar(ALEX, NUEVA)
        self.assertEqual(codigo, 200, cuerpo)
        self.assertTrue(cuerpo['mfa_required'])
        self.assertEqual(cliente.get(AUTH + '/me')[0], 401)   # sin sesión hasta el código
        codigo, cuerpo = cliente.post(AUTH + '/mfa/verify', {'mfa_token': cuerpo['mfa_token'],
                                                             'code': sesion.next_code(ALEX)})
        self.assertEqual(codigo, 200, cuerpo)

    def test_6_contrasena_comun_o_corta_gasta_el_token(self):
        token = self.token_nuevo(MAYA)
        codigo, cuerpo = confirmar(token, COMUN)
        self.assertEqual(codigo, 400)
        self.assertIn('muy común', cuerpo['detail'])
        self.assertIn('pide otro', cuerpo['detail'])
        self.assertEqual(self.bitacora(MAYA, 'auth.password_reset_rejected'), {'reason': 'common'})
        self.assertEqual(confirmar(token), (400, {'detail': INVALIDO}))   # el token ya se gastó
        token = self.token_nuevo(MAYA)
        codigo, cuerpo = confirmar(token, 'corta')
        self.assertEqual(codigo, 400)
        self.assertIn('entre 12 y 128', cuerpo['detail'])
        self.assertEqual(self.bitacora(MAYA, 'auth.password_reset_rejected'), {'reason': 'length'})
        self.assertEqual(confirmar(token), (400, {'detail': INVALIDO}))
        self.assertEqual(entrar(MAYA, sesion.PASSWORD)[1][0], 200)   # la contraseña no cambió

    def test_7_el_cuarto_pedido_en_la_hora_no_envia(self):
        for _ in range(4):
            self.assertEqual(pedir(DANA)[0], 202)   # la misma respuesta también la cuarta vez
        time.sleep(2)
        recibidos = esperar_correos(DANA, 3)
        self.assertEqual(len(recibidos), 3)
        for correo in recibidos:
            token_de(correo)
        # La ventana es de una hora, no de los 15 min del enlace para entrar.
        llave = 'pwreset:req:email:' + hashlib.sha256(DANA.encode()).hexdigest()
        self.assertGreater(self.valkey.ttl(llave), 15 * 60)

    def test_8_si_resend_no_acepta_el_enlace_no_sirve_y_queda_el_motivo(self):
        antes = len(correos(DANA))
        _falso('POST', '/respuesta', {'codigo': 429})
        try:
            self.assertEqual(pedir(DANA)[0], 202)
            token = token_de(esperar_correos(DANA, antes + 1)[-1])
        finally:
            _falso('POST', '/respuesta', {'codigo': 200})
        time.sleep(0.5)
        self.assertEqual(confirmar(token), (400, {'detail': INVALIDO}))
        self.assertEqual(self.bitacora(DANA, 'auth.password_reset_send_failed'), {'reason': '429'})

    def test_9_ningun_token_ni_contrasena_queda_en_la_bitacora(self):
        self.assertGreaterEqual(len(TOKENS), 10)
        for secreto in TOKENS + [NUEVA, COMUN]:
            with self.subTest(secreto=secreto[:6]):
                self.assertEqual(self.pg.execute('SELECT count(*) FROM audit_log WHERE details::text LIKE %s',
                                                 ('%' + secreto + '%',)).fetchone()[0], 0)
        # Para revisar_log.sh: los tokens tampoco deben estar en el log de la API.
        for token in TOKENS:
            print('TOKEN_VISTO', token)


if __name__ == '__main__':
    unittest.main(verbosity=2)

"""Iniciar sesión con un enlace al correo (#28, RC-63): el Hecho cuando, en un compose aislado y sin red.

Corre dentro del servicio `pruebas` de pruebas/enlace/docker-compose.yml, en una red interna sin salida a internet,
contra una API nueva cuyo Resend es el simulado de pruebas/enlace/correo_falso.py. Nunca toca cirdan-pg16:

    C='docker compose -p backkl-enlace -f docker-compose.yml -f pruebas/enlace/docker-compose.yml'
    $C up -d --build --wait db valkey api correo-falso
    $C run --rm pruebas | tee enlace.log
    sh pruebas/enlace/revisar_log.sh enlace.log      # los tokens tampoco están en el log de la API
    $C down -v

Fuera de ese compose (sin ENLACE_CORREO_FALSO) se salta. Pone sin MFA a maya, jordan y admin@olmardo.com en esa base
desechable; alex sigue con MFA. Todas las peticiones salen de la IP del contenedor, así que cada prueba borra el
contador de pedidos de la IP al empezar.
"""
import json
import os
import re
import time
import unittest
import urllib.request
from pathlib import Path

from pruebas import sesion
from pruebas.sesion import Client

FALSO = os.environ.get('ENLACE_CORREO_FALSO')
AUTH = sesion.AUTH
MAYA, JORDAN, DANA, ALEX = ('maya.reed@acme-demo.mx', 'jordan.tate@acme-demo.mx', 'dana.cruz@beta-corp.mx',
                            'alex.morgan@acme-demo.mx')
OLMARDO = 'admin@olmardo.com'
NADIE = 'nadie.existe@acme-demo.mx'
ENLACE = re.compile(r'http://portal\.prueba/login/enlace#t=([A-Za-z0-9_-]+)')
INVALIDO = 'El enlace no es válido o ya venció. Pide otro o entra con tu contraseña.'
TOKENS = []  # cada token visto, para buscarlo en audit_log y en el log de la API
# El hash de relleno de las cuentas de demo apagadas. Se lee del archivo: importar cirdan.auth.demo pide las
# variables de la base que el servicio `pruebas` no tiene.
HASH_DE_RELLENO = re.search(r"^HASH_DE_RELLENO = '([^']+)'", (Path(__file__).resolve().parents[1] / 'cirdan' / 'auth' /
                            'demo.py').read_text(encoding='utf-8'), re.M).group(1)


def _falso(metodo, ruta, datos=None):
    req = urllib.request.Request(FALSO + ruta, method=metodo, data=json.dumps(datos).encode() if datos else None,
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read() or b'null')


def correos(para=None):
    return [c for c in _falso('GET', '/correos') if para is None or c['correo']['to'] == [para]]


def esperar_correos(para, cuantos, plazo=8):
    """El envío corre después del 202: espera a que el simulado reciba `cuantos` para ese correo."""
    fin = time.time() + plazo
    while time.time() < fin:
        recibidos = correos(para)
        if len(recibidos) >= cuantos:
            return recibidos
        time.sleep(0.2)
    return correos(para)


def token_de(correo):
    token = ENLACE.search(correo['correo']['text']).group(1)
    TOKENS.append(token)
    return token


def pedir(email):
    cliente = Client()
    return cliente.post(AUTH + '/link/request', {'email': email, 'captcha': sesion.captcha(cliente)})


def canjear(token, cliente=None):
    cliente = cliente or Client()
    return cliente, cliente.post(AUTH + '/link/verify', {'token': token})


@unittest.skipUnless(FALSO, 'Corre en el compose aislado de pruebas/enlace (ENLACE_CORREO_FALSO)')
class EnlaceAislado(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        import redis
        cls.pg = psycopg.connect(host=os.environ['PGHOST'], port=os.environ.get('PGPORT', '5432'), dbname='cirdan',
                                 user=os.environ.get('POSTGRES_USER', 'postgres'),
                                 password=os.environ['POSTGRES_PASSWORD'], autocommit=True)
        cls.valkey = redis.Redis.from_url(os.environ['VALKEY_URL'], decode_responses=True)
        cls.pg.execute("UPDATE users SET mfa_enabled_at = NULL, totp_secret_enc = NULL WHERE email IN (%s, %s, %s)",
                       (MAYA, JORDAN, OLMARDO))
        # Desde cero también al repetirla sin bajar el compose: tokens, contadores de pedidos y del día.
        for llave in cls.valkey.scan_iter('link*'):
            cls.valkey.delete(llave)
        _falso('DELETE', '/correos')
        # La bitácora no se puede borrar: al repetir sin bajar el compose solo cuenta lo de esta corrida.
        cls.desde = cls.pg.execute('SELECT clock_timestamp()').fetchone()[0]

    @classmethod
    def tearDownClass(cls):
        # Sin cerrar, psycopg deja un ResourceWarning después del OK de unittest.
        cls.pg.close()
        cls.valkey.close()

    def setUp(self):
        for llave in self.valkey.scan_iter('link:req:ip:*'):
            self.valkey.delete(llave)

    def bitacora(self, email, accion):
        """details del último registro de esa acción de esa cuenta, o None."""
        fila = self.pg.execute(
            'SELECT a.details FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = %s AND a.action = %s'
            ' AND a.occurred_at >= %s ORDER BY a.chain_seq DESC LIMIT 1', (email, accion, self.desde)).fetchone()
        return fila[0] if fila else None

    def test_1_correo_que_existe_y_que_no_dan_la_misma_respuesta(self):
        respuestas = [pedir(MAYA), pedir(NADIE)]
        self.assertEqual(respuestas[0], respuestas[1])
        codigo, cuerpo = respuestas[0]
        self.assertEqual(codigo, 202)
        self.assertIn('contraseña', cuerpo['detail'])
        self.assertIn('passkey', cuerpo['detail'])
        recibidos = esperar_correos(MAYA, 1)
        self.assertEqual(len(recibidos), 1)
        time.sleep(1)
        self.assertEqual(correos(NADIE), [])  # al que no existe no se le manda nada
        correo = recibidos[0]
        self.assertEqual(correo['authorization'], 'Bearer prueba-sin-red')
        self.assertEqual(correo['correo']['from'], 'LowTide <acceso@lowtidesec.com>')
        token = token_de(correo)
        self.assertGreaterEqual(len(token), 43)  # 32 bytes en base64 url-safe
        # Solo el enlace y cuánto dura: nada de la cuenta, la empresa ni la IP.
        for texto in (correo['correo']['text'], correo['correo']['html']):
            self.assertIn('15 minutos', texto)
            self.assertNotIn('Acme', texto)
            self.assertNotIn(MAYA, texto)
        self.assertEqual(self.bitacora(MAYA, 'auth.link_sent'), {'expires_minutes': 15})

    def test_2_el_token_entra_una_vez_y_pedir_otro_anula_el_anterior(self):
        self.assertEqual(pedir(JORDAN)[0], 202)
        primero = token_de(esperar_correos(JORDAN, 1)[-1])
        self.assertEqual(pedir(JORDAN)[0], 202)
        segundo = token_de(esperar_correos(JORDAN, 2)[-1])
        self.assertNotEqual(primero, segundo)
        self.assertEqual(canjear(primero)[1], (401, {'detail': INVALIDO}))   # lo anuló el segundo
        self.assertEqual(self.bitacora(JORDAN, 'auth.link_rejected'), {'reason': 'replaced'})   # M3
        cliente, (codigo, cuerpo) = canjear(segundo)
        self.assertEqual(codigo, 200, cuerpo)
        self.assertEqual((cuerpo['mfa_required'], cuerpo['user']['email']), (False, JORDAN))
        self.assertEqual(cliente.get(AUTH + '/me')[0], 200)
        self.assertEqual(canjear(segundo)[1], (401, {'detail': INVALIDO}))   # la segunda vez
        self.assertEqual(self.bitacora(JORDAN, 'auth.login_succeeded'), {'via': 'link'})

    def test_3_vencido_da_401(self):
        self.assertEqual(pedir(OLMARDO)[0], 202)
        token = token_de(esperar_correos(OLMARDO, 1)[-1])
        vencidas = 0
        for llave in self.valkey.scan_iter('link:*'):
            if not llave.startswith(('link:req:', 'link:day:')):
                vencidas += self.valkey.pexpire(llave, 1)
        self.assertGreaterEqual(vencidas, 1)
        time.sleep(0.2)
        self.assertEqual(canjear(token)[1], (401, {'detail': INVALIDO}))
        self.assertEqual(self.bitacora(OLMARDO, 'auth.link_rejected'), {'reason': 'expired'})   # M3

    def test_4_cuenta_desactivada_se_rechaza_y_queda_en_la_bitacora(self):
        self.assertEqual(pedir(OLMARDO)[0], 202)
        token = token_de(esperar_correos(OLMARDO, 2)[-1])
        self.pg.execute('UPDATE users SET is_active = false WHERE email = %s', (OLMARDO,))
        try:
            self.assertEqual(canjear(token)[1], (401, {'detail': INVALIDO}))
        finally:
            self.pg.execute('UPDATE users SET is_active = true WHERE email = %s', (OLMARDO,))
        self.assertEqual(self.bitacora(OLMARDO, 'auth.link_rejected'), {'reason': 'inactive'})

    def test_5_el_cuarto_pedido_seguido_no_envia(self):
        for _ in range(4):
            self.assertEqual(pedir(DANA)[0], 202)   # la misma respuesta también la cuarta vez
        time.sleep(2)
        recibidos = esperar_correos(DANA, 3)
        self.assertEqual(len(recibidos), 3)
        for correo in recibidos:
            token_de(correo)

    def test_6_con_mfa_pide_el_codigo(self):
        self.assertEqual(pedir(ALEX)[0], 202)
        token = token_de(esperar_correos(ALEX, 1)[-1])
        cliente, (codigo, cuerpo) = canjear(token)
        self.assertEqual(codigo, 200, cuerpo)
        self.assertTrue(cuerpo['mfa_required'])
        self.assertNotIn('user', cuerpo)
        self.assertEqual(cliente.get(AUTH + '/me')[0], 401)   # sin sesión hasta el código
        codigo, cuerpo = cliente.post(AUTH + '/mfa/verify', {'mfa_token': cuerpo['mfa_token'],
                                                             'code': sesion.next_code(ALEX)})
        self.assertEqual(codigo, 200, cuerpo)
        self.assertEqual(self.bitacora(ALEX, 'auth.login_succeeded'), {'via': 'link_totp'})

    def test_7_si_resend_no_acepta_el_enlace_no_sirve_y_queda_el_motivo(self):
        _falso('POST', '/respuesta', {'codigo': 429})
        try:
            self.assertEqual(pedir(MAYA)[0], 202)
            token = token_de(esperar_correos(MAYA, 2)[-1])
        finally:
            _falso('POST', '/respuesta', {'codigo': 200})
        time.sleep(0.5)
        self.assertEqual(canjear(token)[1], (401, {'detail': INVALIDO}))
        self.assertEqual(self.bitacora(MAYA, 'auth.link_send_failed'), {'reason': '429'})
        self.assertIsNone(self.bitacora(MAYA, 'auth.link_rejected'))   # el que no salió no deja rastro

    def test_7b_token_usado_queda_en_la_bitacora(self):
        # M3: la segunda vez de un token de una cuenta que existe queda como auth.link_rejected, sin el token.
        for llave in self.valkey.scan_iter('link:req:*'):
            self.valkey.delete(llave)
        antes = len(correos(MAYA))
        self.assertEqual(pedir(MAYA)[0], 202)
        token = token_de(esperar_correos(MAYA, antes + 1)[-1])
        self.assertEqual(canjear(token)[1][0], 200)
        self.assertEqual(canjear(token)[1], (401, {'detail': INVALIDO}))
        self.assertEqual(self.bitacora(MAYA, 'auth.link_rejected'), {'reason': 'used'})
        cuenta = 'SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_user_id WHERE u.email = %s' \
                 " AND a.action = 'auth.link_rejected'"
        antes = self.pg.execute(cuenta, (MAYA,)).fetchone()[0]
        for _ in range(3):
            self.assertEqual(canjear(token)[1], (401, {'detail': INVALIDO}))
        self.assertEqual(self.pg.execute(cuenta, (MAYA,)).fetchone()[0], antes)   # reenviarlo no llena la bitácora

    def test_7c_cuenta_de_demo_apagada_ni_recibe_ni_canjea(self):
        # A1: con el hash de relleno (como demo.py la deja en la VM), la cuenta activa y sin MFA no entra por enlace.
        for llave in self.valkey.scan_iter('link:req:*'):
            self.valkey.delete(llave)
        huella = self.pg.execute('SELECT password_hash FROM users WHERE email = %s', (JORDAN,)).fetchone()[0]
        antes = len(correos(JORDAN))
        self.assertEqual(pedir(JORDAN)[0], 202)
        token = token_de(esperar_correos(JORDAN, antes + 1)[-1])
        try:
            self.pg.execute('UPDATE users SET password_hash = %s WHERE email = %s', (HASH_DE_RELLENO, JORDAN))
            self.assertEqual(canjear(token)[1], (401, {'detail': INVALIDO}))   # apagada después de pedirlo
            self.assertEqual(self.bitacora(JORDAN, 'auth.link_rejected'), {'reason': 'demo_off'})
            dia = self.valkey.get('link:day:' + time.strftime('%Y-%m-%d', time.gmtime()))
            self.assertEqual(pedir(JORDAN)[0], 202)   # la misma respuesta
            time.sleep(2)
            self.assertEqual(len(correos(JORDAN)), antes + 1)   # pero no se le manda nada
            self.assertEqual(self.valkey.get('link:day:' + time.strftime('%Y-%m-%d', time.gmtime())), dia)
        finally:
            self.pg.execute('UPDATE users SET password_hash = %s WHERE email = %s', (huella, JORDAN))

    def test_8_ningun_token_queda_en_la_bitacora(self):
        self.assertGreaterEqual(len(TOKENS), 8)
        for token in TOKENS:
            with self.subTest(token=token[:6]):
                self.assertEqual(self.pg.execute('SELECT count(*) FROM audit_log WHERE details::text LIKE %s',
                                                 ('%' + token + '%',)).fetchone()[0], 0)
        # Para revisar_log.sh: los tokens tampoco deben estar en el log de la API.
        for token in TOKENS:
            print('TOKEN_VISTO', token)


if __name__ == '__main__':
    unittest.main(verbosity=2)

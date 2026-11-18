"""Pruebas sin red ni base del código MFA solo con 0 a 9 (RC-315), del logout que borra la sesión primero (RC-314)
y de /login, que cuenta el intento antes de revisar la contraseña (RC-270).

Sin Valkey ni PostgreSQL: los dos se reemplazan por falsos. Corren dentro del contenedor, porque cirdan.auth.routes
importa fastapi, psycopg y redis:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_login_sin_red.py
"""
import contextlib
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import psycopg
import pyotp
import redis
from fastapi import HTTPException, Response
from pydantic import ValidationError

from cirdan.auth import routes, sessions, totp

ARABES = '١٢٣٤٥٦'            # '١٢٣٤٥٦', dígitos arábigo-índicos
ANCHO_COMPLETO = '１２３４５６'    # '１２３４５６'
A_ARABES = str.maketrans('0123456789', '٠١٢٣٤٥٦٧٨٩')
A_ANCHO_COMPLETO = str.maketrans('0123456789', ''.join(chr(0xff10 + i) for i in range(10)))
SECRETO = pyotp.random_base32(32)
AHORA = 1_800_000_000  # reloj fijo: el código válido no cambia a mitad de la prueba


def codigo_valido():
    return pyotp.TOTP(SECRETO, interval=totp.STEP_SECONDS).at(AHORA)


class CodigoSoloAscii(unittest.TestCase):
    def test_1_digitos_unicode_dan_none_sin_excepcion(self):
        for codigo in (ARABES, ANCHO_COMPLETO):
            with self.subTest(codigo=ascii(codigo)):
                self.assertIsNone(totp.verify_code(SECRETO, codigo, now=AHORA))

    def test_2_el_codigo_bueno_escrito_con_otros_digitos_tampoco_entra(self):
        # Con isdigit() estos llegaban a hmac.compare_digest, que lanza TypeError con texto no ASCII.
        bueno = codigo_valido()
        self.assertEqual(totp.verify_code(SECRETO, bueno, now=AHORA), AHORA // totp.STEP_SECONDS)
        for tabla in (A_ARABES, A_ANCHO_COMPLETO):
            with self.subTest(codigo=ascii(bueno.translate(tabla))):
                self.assertIsNone(totp.verify_code(SECRETO, bueno.translate(tabla), now=AHORA))

    def test_3_otras_formas_raras_dan_none(self):
        bueno = codigo_valido()
        for codigo in (bueno + '\n', ' ' + bueno, bueno[:5], bueno + '0', '12345٦', '', None, 123456, b'123456'):
            with self.subTest(codigo=ascii(codigo)):
                self.assertIsNone(totp.verify_code(SECRETO, codigo, now=AHORA))

    def test_4_los_tres_modelos_rechazan_digitos_unicode_y_aceptan_0_a_9(self):
        token = 'x' * 20
        modelos = ((routes.MfaIn, {'mfa_token': token}), (routes.MfaEnableIn, {}),
                   (routes.PasskeyRegisterOptionsIn, {'current_password': 'x'}))
        for modelo, resto in modelos:
            for codigo in (ARABES, ANCHO_COMPLETO, '123456\n', '12345'):
                with self.subTest(modelo=modelo.__name__, codigo=ascii(codigo)), self.assertRaises(ValidationError):
                    modelo(code=codigo, **resto)
            self.assertEqual(modelo(code='012345', **resto).code, '012345')
        self.assertIsNone(routes.PasskeyRegisterOptionsIn(current_password='x').code, 'el código sigue siendo opcional')


class BaseCaida:
    """transaction() que falla como PostgreSQL detenido."""

    def __init__(self):
        self.llamadas = []

    @contextlib.contextmanager
    def __call__(self, org_id):
        self.llamadas.append(org_id)
        raise psycopg.OperationalError('connection refused')
        yield  # nunca llega


class Logout(unittest.TestCase):
    TOKEN = 'token-de-la-cookie-que-no-va-al-log-%d' % int(time.time())

    def setUp(self):
        self.orden = []
        sesion = {'user_id': 'u-1', 'org_id': 'o-actual', 'home_org_id': 'o-casa'}
        self.sessions = mock.patch.multiple(
            routes.sessions,
            get=mock.Mock(side_effect=lambda token: dict(sesion) if token == self.TOKEN else None),
            delete=mock.Mock(side_effect=lambda token: self.orden.append(('valkey', token))))
        self.sessions.start()
        self.addCleanup(self.sessions.stop)
        self.request = SimpleNamespace(cookies={routes.COOKIE: self.TOKEN}, client=SimpleNamespace(host='203.0.113.7'))

    def _cookie_borrada(self, response, secure=None):
        # El navegador solo reemplaza la cookie si el borrado lleva el mismo nombre, Path y Secure que el set_cookie
        # de _start_session. HttpOnly y SameSite se revisan para que el borrado no quede más débil que la cookie.
        cookies = [v.decode() for k, v in response.raw_headers if k == b'set-cookie']
        self.assertEqual(len(cookies), 1, cookies)
        self.assertTrue(cookies[0].startswith(routes.COOKIE + '="";'), cookies)
        partes = [p.strip() for p in cookies[0].split(';')[1:]]
        attrs = {p.split('=', 1)[0].lower(): (p.split('=', 1)[1] if '=' in p else True) for p in partes}
        self.assertEqual(attrs.get('max-age'), '0', cookies)
        self.assertEqual(attrs.get('path'), '/', cookies)
        self.assertIs(attrs.get('httponly'), True, cookies)
        self.assertEqual(str(attrs.get('samesite')).lower(), 'lax', cookies)
        self.assertEqual('secure' in attrs, routes.COOKIE_SECURE if secure is None else secure, cookies)

    def _sin_token(self, logs):
        texto = '\n'.join(logs.output)
        self.assertNotIn(self.TOKEN, texto, 'el log nunca lleva el token')
        return texto

    def test_1_con_la_base_caida_borra_sesion_y_cookie_y_no_lanza(self):
        caida, response = BaseCaida(), Response()
        with mock.patch.object(routes, 'transaction', caida), self.assertLogs(routes.log, 'ERROR') as logs:
            self.assertIsNone(routes.logout(self.request, response))
        self.assertEqual(self.orden, [('valkey', self.TOKEN)], 'la sesión se borra de Valkey')
        self.assertEqual(caida.llamadas, ['o-casa'], 'se intentó escribir en la empresa de la cuenta')
        self._cookie_borrada(response)
        texto = '\n'.join(logs.output)
        self.assertIn('auth.logout', texto)
        self.assertIn('u-1', texto, 'el log lleva el id del usuario')
        self.assertNotIn(self.TOKEN, texto, 'el log nunca lleva el token')

    def test_2_con_la_base_arriba_escribe_el_evento_despues_de_borrar(self):
        conexion, response = object(), Response()

        @contextlib.contextmanager
        def transaccion(org_id):
            self.orden.append(('base', org_id))
            yield conexion

        with mock.patch.object(routes, 'transaction', transaccion), mock.patch.object(routes, 'audit') as audit:
            routes.logout(self.request, response)
        self.assertEqual(self.orden, [('valkey', self.TOKEN), ('base', 'o-casa')], 'primero Valkey y luego la base')
        audit.assert_called_once_with(conexion, 'o-casa', 'auth.logout', 'u-1', '203.0.113.7', 'user', 'u-1')
        self._cookie_borrada(response)

    def test_3_sin_sesion_borra_la_cookie_y_no_toca_la_base(self):
        response = Response()
        self.request.cookies = {routes.COOKIE: 'otra'}
        with mock.patch.object(routes, 'transaction', BaseCaida()) as caida:
            routes.logout(self.request, response)
        self.assertEqual(caida.llamadas, [])
        self._cookie_borrada(response)

    def test_4_si_valkey_falla_al_leer_borra_la_cookie_intenta_borrar_y_no_lanza(self):
        # Antes de RC-314 la excepción salía del logout: 500 sin Set-Cookie y la cookie seguía en el navegador.
        for falla in (redis.ConnectionError('Valkey caído'), redis.TimeoutError('Timeout reading from socket')):
            with self.subTest(falla=type(falla).__name__):
                self.orden.clear()
                routes.sessions.get.side_effect = falla
                caida, response = BaseCaida(), Response()
                with mock.patch.object(routes, 'transaction', caida), self.assertLogs(routes.log, 'ERROR') as logs:
                    self.assertIsNone(routes.logout(self.request, response))
                self.assertEqual(self.orden, [('valkey', self.TOKEN)], 'se intenta borrar la sesión igual')
                self.assertEqual(caida.llamadas, [], 'sin datos de la sesión no se escribe el evento')
                self._cookie_borrada(response)
                self.assertIn('leer la sesión', self._sin_token(logs))

    def test_5_si_valkey_falla_al_borrar_borra_la_cookie_no_escribe_el_evento_y_no_lanza(self):
        for falla in (redis.ConnectionError('Valkey caído'), redis.TimeoutError('Timeout reading from socket')):
            with self.subTest(falla=type(falla).__name__):
                routes.sessions.delete.side_effect = falla
                caida, response = BaseCaida(), Response()
                with mock.patch.object(routes, 'transaction', caida), self.assertLogs(routes.log, 'ERROR') as logs:
                    self.assertIsNone(routes.logout(self.request, response))
                routes.sessions.delete.assert_called_with(self.TOKEN)
                self.assertEqual(caida.llamadas, [], 'la sesión puede seguir en Valkey: no se escribe auth.logout')
                self._cookie_borrada(response)
                texto = self._sin_token(logs)
                self.assertIn('borrar de Valkey', texto)
                self.assertIn('u-1', texto, 'el log lleva el id del usuario')

    def test_6_si_valkey_falla_al_leer_y_al_borrar_igual_borra_la_cookie(self):
        routes.sessions.get.side_effect = redis.ConnectionError('Valkey caído')
        routes.sessions.delete.side_effect = redis.ConnectionError('Valkey caído')
        caida, response = BaseCaida(), Response()
        with mock.patch.object(routes, 'transaction', caida), self.assertLogs(routes.log, 'ERROR') as logs:
            self.assertIsNone(routes.logout(self.request, response))
        self.assertEqual(caida.llamadas, [])
        self._cookie_borrada(response)
        self.assertIn('desconocido', self._sin_token(logs))

    def test_7_el_borrado_lleva_secure_cuando_la_cookie_lo_lleva(self):
        for secure in (True, False):
            with self.subTest(secure=secure), mock.patch.object(routes, 'COOKIE_SECURE', secure), \
                    mock.patch.object(routes, 'transaction', BaseCaida()):
                response = Response()
                self.request.cookies = {routes.COOKIE: 'otra'}
                routes.logout(self.request, response)
                self._cookie_borrada(response, secure=secure)


class ValkeyConMulti:
    """Lo que usa el bloqueo del login: pipeline (MULTI, todo junto bajo un candado), get, set, delete y los dos
    scripts de sessions.py (_TAKE y _REFUND), escritos aquí en Python porque sin Valkey no hay Lua. Guarda el
    vencimiento de cada llave con un reloj propio en ms (ahora), que la prueba adelanta: una llave vencida desaparece
    como en Valkey, EXPIRE con nx no toca una llave que ya vence y PEXPIRETIME da -2 sin llave y -1 sin vencimiento.
    Los scripts reales se prueban con Valkey en test_auth.py (test_20 a test_22)."""

    def __init__(self):
        self.datos, self.vence, self.ahora, self.candado = {}, {}, 1_800_000_000_000, threading.Lock()

    def _vigente(self, llave):
        if llave in self.vence and self.vence[llave] <= self.ahora:
            del self.datos[llave], self.vence[llave]
        return self.datos.get(llave)

    def _incr(self, llave):
        self.datos[llave] = int(self._vigente(llave) or 0) + 1
        return self.datos[llave]

    def _expire(self, llave, segundos, nx):
        if self._vigente(llave) is None or (nx and llave in self.vence):
            return False
        self.vence[llave] = self.ahora + int(segundos) * 1000
        return True

    def _pexpiretime(self, llave):
        return -2 if self._vigente(llave) is None else self.vence.get(llave, -1)

    def adelantar(self, segundos):
        with self.candado:
            self.ahora += int(segundos * 1000)

    def ttl(self, llave):
        with self.candado:
            vence = self._pexpiretime(llave)
            return vence if vence < 0 else (vence - self.ahora) // 1000

    def get(self, llave):
        with self.candado:
            return self._vigente(llave)

    def mget(self, *llaves):
        with self.candado:
            return [self._vigente(llave) for llave in llaves]

    def set(self, llave, valor, ex=None, **_):
        with self.candado:
            self.datos[llave] = valor
            self.vence.pop(llave, None)
            if ex:
                self._expire(llave, ex, nx=False)

    def delete(self, *llaves):
        with self.candado:
            for llave in llaves:
                self.datos.pop(llave, None)
                self.vence.pop(llave, None)

    def pipeline(self):
        valkey, ops = self, []

        class Tubo:
            def incr(self, llave):
                ops.append(lambda: valkey._incr(llave))

            def expire(self, llave, segundos, nx=False):
                ops.append(lambda: valkey._expire(llave, segundos, nx))

            def execute(self):
                with valkey.candado:
                    return [op() for op in ops]

        return Tubo()

    def eval(self, script, numkeys, *args):
        llaves, argv = args[:numkeys], args[numkeys:]
        with self.candado:
            if script == sessions._TAKE:
                if any(int(self._vigente(llave) or 0) >= int(argv[i]) for i, llave in enumerate(llaves)):
                    return 0
                for llave in llaves:
                    self._incr(llave)
                    self._expire(llave, argv[2], nx=True)
                return [self._pexpiretime(llave) for llave in llaves]
            assert script == sessions._REFUND, 'solo los scripts del bloqueo del login'
            for i, llave in enumerate(llaves):
                if self._pexpiretime(llave) == int(argv[i]) and int(self._vigente(llave) or 0) > 0:
                    self.datos[llave] = int(self.datos[llave]) - 1
            return None


class CarrerasDelLogin(unittest.TestCase):
    """RC-270: 30 contraseñas a la vez solo llegan 5 a revisión, exista o no el correo. La revisión tarda 50 ms, como
    argon2: con el bloqueo revisado antes y el fallo contado después, las 30 pasaban con el contador en 0."""
    EMAIL, IP, N = 'carrera@ejemplo.test', '203.0.113.9', 30

    def setUp(self):
        self.valkey, self.revisadas, self.fila, self.buena = ValkeyConMulti(), [], None, False
        self.candado, self.durante = threading.Lock(), None

        def revisar(*_):
            time.sleep(0.05)
            with self.candado:
                self.revisadas.append(1)
            if self.durante:  # lo que pasa mientras se revisa la contraseña
                durante, self.durante = self.durante, None
                durante()
            return self.buena

        @contextlib.contextmanager
        def transaccion(org_id=None):
            yield SimpleNamespace(execute=lambda *a: SimpleNamespace(fetchone=lambda: self.fila))

        for parche in (mock.patch.object(sessions, '_valkey', lambda: self.valkey),
                       mock.patch.object(routes.captcha, 'verify', lambda _: True),
                       mock.patch.object(routes, 'client_ip', lambda _: self.IP),
                       mock.patch.object(routes, 'transaction', transaccion),
                       mock.patch.object(routes.passwords, 'verify_password', revisar),
                       mock.patch.object(routes.passwords, 'burn_time', revisar),
                       mock.patch.object(routes.passwords, 'needs_rehash', lambda *_: False)):
            parche.start()
            self.addCleanup(parche.stop)

    def _login(self, password='CIRDAN_FAKE_mala', email=None):
        try:
            salida = routes.login(routes.LoginIn(email=email or self.EMAIL, password=password, captcha='x'), None,
                                  Response())
        except HTTPException as e:
            return e.status_code
        return getattr(salida, 'status_code', 200)

    def _en_paralelo(self):
        salida = threading.Barrier(self.N)

        def uno(_):
            salida.wait()
            return self._login()

        hilos, codigos = [], []
        for n in range(self.N):
            hilos.append(threading.Thread(target=lambda n=n: codigos.append(uno(n))))
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        return sorted(codigos)

    def _contador(self, llave):
        return int(self.valkey.get(llave) or 0)

    def _correo(self, email=None):
        return self._contador(sessions._email_key(email or self.EMAIL))

    def _ip(self):
        return self._contador(sessions._ip_key(self.IP))

    def _con_cuenta(self, mfa=True):
        self.fila = {'organization_id': 'o-1', 'user_id': 'u-1', 'password_hash': 'x', 'mfa_enabled': mfa}

    def test_1_con_el_correo_que_existe_solo_cinco_contrasenas_se_revisan(self):
        self._con_cuenta(mfa=False)
        self.assertEqual(self._en_paralelo(), [401] * sessions.MAX_FAILS_EMAIL + [429] * (self.N - sessions.MAX_FAILS_EMAIL))
        self.assertEqual(len(self.revisadas), sessions.MAX_FAILS_EMAIL)
        self.assertEqual((self._correo(), self._ip()), (5, 5), 'los 25 que recibieron 429 no cuentan')

    def test_2_con_el_correo_que_no_existe_tambien_solo_cinco(self):
        # El intento cuenta antes de buscar el correo: el 429 sale igual exista o no la cuenta.
        self.assertEqual(self._en_paralelo(), [401] * sessions.MAX_FAILS_EMAIL + [429] * (self.N - sessions.MAX_FAILS_EMAIL))
        self.assertEqual(len(self.revisadas), sessions.MAX_FAILS_EMAIL)

    def test_3_la_contrasena_buena_devuelve_el_intento_al_correo_y_a_la_ip(self):
        # El correo llega con espacios y mayúsculas: take y refund usan el mismo correo normalizado.
        self._con_cuenta()
        escrito = ' Carrera@Ejemplo.TEST '
        for _ in range(3):
            self.assertEqual(self._login(email=escrito), 401)
        self.buena = True
        for _ in range(10):
            self.assertEqual(self._login('CIRDAN_FAKE_buena', email=escrito), 200)
        self.assertEqual(self._correo(), 3, 'solo cuentan las 3 malas, en la llave del correo normalizado')
        self.assertEqual(self._ip(), 3)
        self.assertEqual(sorted(k for k in self.valkey.datos if k.startswith('login:fail:email:')),
                         [sessions._email_key(self.EMAIL)], 'una sola llave de correo')

    def test_4_un_429_no_le_suma_al_otro_contador(self):
        # Ronda 1, hallazgo 1: con la IP en su máximo, cada 429 a un correo ajeno subía ese correo, y al revés.
        self.valkey.set(sessions._ip_key(self.IP), sessions.MAX_FAILS_IP, ex=sessions.LOCK_SECONDS)
        self.assertEqual(self._login(email='ajeno@ejemplo.test'), 429)
        self.assertIsNone(self.valkey.get(sessions._email_key('ajeno@ejemplo.test')), 'el correo ajeno no cuenta')
        self.assertEqual(self._ip(), sessions.MAX_FAILS_IP)
        self.valkey.delete(sessions._ip_key(self.IP))
        self.valkey.set(sessions._email_key(self.EMAIL), sessions.MAX_FAILS_EMAIL, ex=sessions.LOCK_SECONDS)
        self.assertEqual(self._login(), 429)
        self.assertIsNone(self.valkey.get(sessions._ip_key(self.IP)), 'la IP no cuenta')
        self.assertEqual(self.revisadas, [], 'ningún 429 revisa la contraseña')

    def test_5_doble_clic_con_cuatro_fallos_deja_el_codigo_bueno(self):
        # Ronda 1, hallazgo 3: con el correo en 4, el segundo clic llega mientras se revisa la contraseña del primero y
        # recibe 429. Ese 429 no cuenta, así que al devolver el primero el correo vuelve a 4 y el código entra.
        self._con_cuenta()
        self.buena = True
        self.valkey.set(sessions._email_key(self.EMAIL), 4, ex=sessions.LOCK_SECONDS)
        segundo = []
        self.durante = lambda: segundo.append(self._login('CIRDAN_FAKE_buena'))
        self.assertEqual(self._login('CIRDAN_FAKE_buena'), 200)
        self.assertEqual(segundo, [429])
        self.assertEqual((self._correo(), self._ip()), (4, 0))
        self.assertTrue(sessions.take_mfa_attempt(self.EMAIL, self.IP), 'el quinto intento queda para el código')

    def test_6_la_devolucion_no_baja_una_ventana_nueva(self):
        # Ronda 1, hallazgo 4: los contadores vencen mientras se revisa la contraseña buena y otro fallo abre una
        # ventana nueva de 15 min. La devolución ya no es de esa ventana: el fallo nuevo sigue contando.
        self._con_cuenta()
        self.buena = True

        def vence_y_falla_otro():
            self.valkey.adelantar(sessions.LOCK_SECONDS)
            sessions.register_fail(self.EMAIL, self.IP)

        self.durante = vence_y_falla_otro
        self.assertEqual(self._login('CIRDAN_FAKE_buena'), 200)
        self.assertEqual((self._correo(), self._ip()), (1, 1))
        self.assertEqual(self.valkey.ttl(sessions._email_key(self.EMAIL)), sessions.LOCK_SECONDS)

    def test_7_si_la_base_o_la_huella_fallan_el_intento_no_cuenta(self):
        # Ronda 1, hallazgo 2: una excepción entre contar y revisar la contraseña sale como 500, y no es un fallo.
        # También la del relleno de un correo que no existe: si contara solo ahí, el contador diría qué correos existen.
        for donde, error in (('transaction', psycopg.OperationalError('base caída')),
                             ('verify_password', RuntimeError('huella ilegible')),
                             ('burn_time', RuntimeError('relleno ilegible'))):
            with self.subTest(donde=donde):
                self.fila = None
                if donde != 'burn_time':
                    self._con_cuenta()

                def falla(*_, error=error):
                    raise error
                objetivo = routes if donde == 'transaction' else routes.passwords
                with mock.patch.object(objetivo, donde, falla):
                    with self.assertRaises(type(error)):
                        self._login('CIRDAN_FAKE_buena')
                self.assertEqual((self._correo(), self._ip()), (0, 0))

    def test_8_el_vencimiento_es_de_quince_minutos_desde_el_primer_fallo(self):
        # Los contadores vencen con el primer fallo (EXPIRE NX) y los siguientes no los renuevan: a los 15 min del
        # primero se puede volver a intentar.
        self._con_cuenta()
        for _ in range(sessions.MAX_FAILS_EMAIL):
            self.assertEqual(self._login(), 401)
            self.valkey.adelantar(60)
        self.assertEqual(self._login(), 429)
        restante = sessions.LOCK_SECONDS - 60 * sessions.MAX_FAILS_EMAIL
        self.assertEqual(self.valkey.ttl(sessions._email_key(self.EMAIL)), restante)
        self.assertEqual(self.valkey.ttl(sessions._ip_key(self.IP)), restante)
        self.valkey.adelantar(restante)
        self.assertEqual(self._login(), 401)
        self.assertEqual((self._correo(), self._ip()), (1, 1))


if __name__ == '__main__':
    unittest.main()

"""Pruebas de la revisión de contraseñas filtradas con Pwned Passwords (RC-334), sin red ni base.

Cubren los puntos 1 a 5 del Hecho cuando de RC-334: solo salen los 5 primeros caracteres hex del SHA-1 con
'Add-Padding: true', el resto se compara aquí, el relleno con 0 no cuenta, ni la contraseña ni el SHA-1 van al log,
una filtrada da 400 por POST /api/v1/auth/password sin cambiar nada, una que no sale da 200 (desde RC-331 la ruta
responde 200 con passkeys_removed, no 204), sin respuesta en 2 s se sigue con la lista de RC-281 y queda el evento, y
la variable apaga la revisión. `http.client.HTTPSConnection` se reemplaza por un falso y cualquier socket real hace
fallar la prueba. Corren dentro del contenedor, porque importan argon2, cryptography y la API:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_contrasenas_filtradas.py
"""
import hashlib
import http.client
import io
import json
import os
import secrets
import socket
import threading
import time
from contextlib import contextmanager
from unittest import mock

from cirdan.auth import passwords, routes, sessions
from cirdan.auth.deps import Session
from pruebas.test_llave_huellas import ALEX, CLAVE, ORG, Base

NUEVA = 'Marea-Baja-Filtrada-2026'
OTRA = 'Marea-Baja-Sin-Filtrar-2026'
COMUN = 'aaaaaaaaaaaaaaaa'  # sale en la lista local de RC-281
FILTRADA = 'Esa contraseña salió en una filtración conocida. Elige otra.'
PLAZO_CORTO = 0.2


def sha1(texto):
    return hashlib.sha1(texto.encode('utf-8'), usedforsecurity=False).hexdigest().upper()


def rango(texto=None, conteo=3, relleno=900, fin='\r\n'):
    """Cuerpo de un rango como el de la API: `relleno` líneas al azar con conteo 0 y, con `texto`, su línea."""
    lineas = ['%s:0' % secrets.token_hex(18)[:35].upper() for _ in range(relleno)]
    if texto is not None:
        lineas.insert(relleno // 2, '%s:%d' % (sha1(texto)[5:], conteo))
    return fin.join(lineas)


class Pwned:
    """Hace de http.client.HTTPSConnection: anota cada petición y responde `cuerpo` con `status`. Con `colgar`, no
    responde hasta que se suelta; con `gota`, manda un byte cada 10 ms sin terminar nunca; con `cortar`, la conexión
    se cierra cuando faltan esos bytes del Content-Length. `timeouts` anota cada settimeout del socket."""

    def __init__(self, cuerpo='', status=200, error=None, colgar=False, gota=False, cortar=0):
        self.cuerpo = cuerpo.encode('ascii') if isinstance(cuerpo, str) else cuerpo
        self.status = status
        self.error = error
        self.gota = gota
        self.cortar = cortar
        self.timeouts = []
        self.soltar = threading.Event()
        if not colgar:
            self.soltar.set()
        self.peticiones = []

    def __call__(self, host, timeout=None, context=None):
        return _Conexion(self, host, timeout, context)


class _Conexion:
    def __init__(self, api, host, timeout, context):
        self.api, self.host, self.timeout, self.context = api, host, timeout, context
        self.sock = _Socket(api)

    def request(self, metodo, ruta, headers=None):
        self.api.peticiones.append({'host': self.host, 'metodo': metodo, 'ruta': ruta, 'headers': dict(headers or {}),
                                    'timeout': self.timeout, 'tls': self.context is not None})

    def getresponse(self):
        self.api.soltar.wait(10)
        if self.api.error:
            raise self.api.error
        return _Respuesta(self.api)

    def close(self):
        pass


class _Socket:
    def __init__(self, api):
        self.api = api

    def settimeout(self, segundos):
        self.api.timeouts.append(segundos)

    def fileno(self):
        return 3


class Crudo:
    """Hace de http.client.HTTPSConnection con el http.client real encima de un socket falso: `bytes_` es la respuesta
    entera (línea de estado, encabezados y cuerpo) y cada recv da hasta `paso` bytes. Con `gota`, cada recv tarda 10 ms
    y da un byte de un encabezado que no termina (hasta 5 s). El socket se cierra como uno real: cuando se llamó
    close() y ya no queda ningún makefile abierto, y desde ahí settimeout da OSError y fileno() -1."""

    def __init__(self, bytes_=b'', paso=4096, gota=False):
        self.bytes_, self.paso, self.gota = bytes_, paso, gota
        self.timeouts = []
        self.soltar = threading.Event()
        self.soltar.set()
        self.peticiones = []
        self.socket = None

    def __call__(self, host, timeout=None, context=None):
        api = self

        class Conexion(http.client.HTTPConnection):
            def connect(self):
                api.socket = self.sock = _SocketCrudo(api)

            def request(self, metodo, ruta, headers=None):
                api.peticiones.append({'host': host, 'metodo': metodo, 'ruta': ruta})
                super().request(metodo, ruta, headers=headers or {})
        return Conexion(host, timeout=timeout)


class _SocketCrudo:
    def __init__(self, api):
        self.api, self.resto, self.refs, self.cerrado, self.real_cerrado = api, api.bytes_, 0, False, False
        self.inicio = time.monotonic()

    def sendall(self, datos):
        pass

    def settimeout(self, segundos):
        if self.real_cerrado:
            raise OSError(9, 'Bad file descriptor')
        self.api.timeouts.append(segundos)

    def fileno(self):
        return -1 if self.real_cerrado else 3

    def makefile(self, mode='rb', buffering=None):
        self.refs += 1
        crudo = _CrudoIO(self)
        return crudo if buffering == 0 else io.BufferedReader(crudo)

    def close(self):
        self.cerrado = True
        self.quiza_cerrar()

    def quiza_cerrar(self):
        if self.cerrado and self.refs == 0:
            self.real_cerrado = True


class _CrudoIO(io.RawIOBase):
    def __init__(self, sock):
        super().__init__()
        self.sock = sock

    def readable(self):
        return True

    def readinto(self, b):
        if self.sock.real_cerrado:
            raise OSError(9, 'Bad file descriptor')
        if self.sock.api.gota:
            if time.monotonic() - self.sock.inicio > 5:
                return 0
            time.sleep(0.01)
            parte = b'a' if getattr(self, 'empezo', False) else b'HTTP/1.1 200 OK\r\nX-Gota: '
            self.empezo = True
        else:
            parte, self.sock.resto = self.sock.resto[:min(len(b), self.sock.api.paso)], \
                self.sock.resto[min(len(b), self.sock.api.paso):]
        b[:len(parte)] = parte
        return len(parte)

    def close(self):
        if not self.closed:
            self.sock.refs -= 1
            self.sock.quiza_cerrar()
        super().close()


def http_(cuerpo, *encabezados, version='HTTP/1.1'):
    cuerpo = cuerpo.encode('ascii')
    cabeza = [version + ' 200 OK', 'Content-Type: text/plain', 'Content-Length: %d' % len(cuerpo), *encabezados]
    return ('\r\n'.join(cabeza) + '\r\n\r\n').encode('ascii') + cuerpo


class _Respuesta:
    """Como http.client.HTTPResponse con Content-Length: `length` baja con cada read1 y, si la conexión se cierra
    antes, se queda con lo que faltaba sin lanzar nada. No tiene read(n), que en un socket real junta recv hasta
    llenar n bytes sin dejar revisar el tope entre uno y otro: la lectura va con read1."""

    def __init__(self, api):
        self.api = api
        self.status = api.status
        self.resto = api.cuerpo[:len(api.cuerpo) - api.cortar]
        self.length = None if api.gota else len(api.cuerpo)

    def read1(self, n):
        if self.api.gota:
            time.sleep(0.01)
            return b'0'
        parte, self.resto = self.resto[:n], self.resto[n:]
        if self.length is not None:
            self.length -= len(parte)
        return parte


def sin_red(*args, **kw):
    raise AssertionError('la prueba intentó abrir una conexión real')


class Filtradas(Base):
    """Base de las pruebas: la API de Pwned Passwords falsa, sin sockets reales y un cupo nuevo por prueba."""

    def setUp(self):
        self._vars = {}
        super().setUp()
        self.env(PWNED_PASSWORDS_ENABLED='true')
        for nombre in ('create_connection', 'getaddrinfo'):
            p = mock.patch.object(socket, nombre, sin_red)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(passwords, '_pwned_cupo', threading.BoundedSemaphore(passwords.PWNED_EN_CURSO))
        p.start()
        self.addCleanup(p.stop)
        self.api = None
        # Va después del cupo: corre antes de devolverlo, así ningún hilo libera el cupo de otra prueba.
        self.addCleanup(self.esperar_hilos)

    def env(self, **valores):
        """Base.env borra las variables que no recibe; aquí se suman a las de antes."""
        self._vars.update(valores)
        super().env(**self._vars)

    def responder(self, **kw):
        self.api = Pwned(**kw)
        p = mock.patch.object(passwords.http.client, 'HTTPSConnection', self.api)
        p.start()
        self.addCleanup(p.stop)
        return self.api

    def plazo(self, segundos=PLAZO_CORTO):
        p = mock.patch.object(passwords, 'PWNED_PLAZO', segundos)
        p.start()
        self.addCleanup(p.stop)

    def esperar_hilos(self, tope=5):
        if self.api:
            self.api.soltar.set()
        fin = time.monotonic() + tope
        for hilo in threading.enumerate():
            if hilo.name == 'pwned-passwords':
                hilo.join(max(0, fin - time.monotonic()))
        return [h for h in threading.enumerate() if h.name == 'pwned-passwords']

    def assert_sin_rastro(self, texto, *contrasenas):
        for c in contrasenas:
            self.assertNotIn(c, texto)
            self.assertNotIn(sha1(c), texto)
            self.assertNotIn(sha1(c)[5:], texto)
            self.assertNotIn(sha1(c).lower(), texto)


class Consulta(Filtradas):
    """Punto 1: lo que sale, lo que se compara aquí y lo que va al log."""

    def test_1_solo_salen_5_caracteres_hex_del_sha1_con_add_padding(self):
        api = self.responder(cuerpo=rango(NUEVA))
        self.assertIs(passwords.filtrada(NUEVA), True)
        self.assertEqual(len(api.peticiones), 1)
        peticion = api.peticiones[0]
        self.assertEqual((peticion['host'], peticion['metodo'], peticion['tls']), ('api.pwnedpasswords.com', 'GET', True))
        self.assertEqual(peticion['ruta'], '/range/' + sha1(NUEVA)[:5])
        self.assertRegex(peticion['ruta'], r'^/range/[0-9A-F]{5}$')
        self.assertEqual(peticion['headers'].get('Add-Padding'), 'true')
        self.assertEqual(peticion['timeout'], passwords.PWNED_PLAZO)
        self.assert_sin_rastro(json.dumps(peticion), NUEVA)

    def test_1b_una_que_no_sale_da_false(self):
        self.responder(cuerpo=rango(OTRA))
        self.assertIs(passwords.filtrada(NUEVA), False)

    def test_1c_el_resto_se_compara_sin_importar_mayusculas_ni_fin_de_linea(self):
        for fin in ('\r\n', '\n'):
            for minusculas in (False, True):
                with self.subTest(fin=repr(fin), minusculas=minusculas):
                    cuerpo = rango(NUEVA, fin=fin)
                    self.responder(cuerpo=cuerpo.lower() if minusculas else cuerpo)
                    self.assertIs(passwords.filtrada(NUEVA), True)

    def test_1d_el_relleno_con_0_no_cuenta(self):
        self.responder(cuerpo=rango(NUEVA, conteo=0))
        self.assertIs(passwords.filtrada(NUEVA), False)
        self.responder(cuerpo=rango(NUEVA, conteo=0) + '\r\n' + rango(NUEVA, conteo=1, relleno=0))
        self.assertIs(passwords.filtrada(NUEVA), True)

    def test_1e_ni_la_contrasena_ni_el_sha1_van_al_log(self):
        for caso, kw in (('sale', {'cuerpo': rango(NUEVA)}), ('no sale', {'cuerpo': rango(OTRA)})):
            with self.subTest(caso=caso):
                self.responder(**kw)
                with self.assertNoLogs('cirdan.auth.passwords', 'DEBUG'):
                    passwords.filtrada(NUEVA)
        self.plazo()
        casos = {'HTTP 503': {'status': 503}, 'error': {'error': OSError('/range/' + sha1(NUEVA)[:5])},
                 'otra forma': {'cuerpo': NUEVA + ':' + sha1(NUEVA)}, 'colgada': {'colgar': True}}
        for caso, kw in casos.items():
            with self.subTest(caso=caso):
                self.responder(**kw)
                with self.assertLogs('cirdan.auth.passwords', 'DEBUG') as logs:
                    self.assertIsNone(passwords.filtrada(NUEVA))
                self.assert_sin_rastro('\n'.join(logs.output), NUEVA)
                self.assertEqual(self.esperar_hilos(), [])


class SinRespuesta(Filtradas):
    """Punto 3: sin respuesta completa en 2 s se sigue solo con la lista local."""

    def test_3_el_plazo_es_de_2_segundos(self):
        self.assertEqual(passwords.PWNED_PLAZO, 2.0)

    def test_3b_colgada_da_none_al_vencer_el_plazo(self):
        self.plazo()
        self.responder(colgar=True)
        inicio = time.monotonic()
        self.assertIsNone(passwords.filtrada(NUEVA))
        tardo = time.monotonic() - inicio
        self.assertGreaterEqual(tardo, PLAZO_CORTO * 0.9)
        self.assertLess(tardo, PLAZO_CORTO + 0.5)

    def test_3c_respuestas_malas_dan_none(self):
        self.plazo()
        casos = {'HTTP 429': {'status': 429}, 'HTTP 500': {'status': 500}, 'conexión': {'error': ConnectionResetError()},
                 'tls': {'error': OSError('tls')}, 'otra forma': {'cuerpo': 'esto no es un rango'},
                 'no ascii': {'cuerpo': 'Ñ'.encode('utf-8')},
                 'más de 1 MB': {'cuerpo': rango(NUEVA, relleno=30000)},
                 # Ronda 1, hallazgo 3: un 200 vacío, cortado en un fin de línea o sin el relleno daba False.
                 '200 vacío': {'cuerpo': ''},
                 'sin relleno': {'cuerpo': rango(NUEVA, relleno=passwords.PWNED_MIN_LINEAS - 2)}}
        self.assertGreater(len(casos['más de 1 MB']['cuerpo']), passwords.PWNED_TOPE)
        # Cortada justo antes de la línea de la contraseña, con más de 800 líneas ya leídas: solo el Content-Length
        # que falta la delata.
        cuerpo = rango(NUEVA, relleno=2000)
        casos['cortada'] = {'cuerpo': cuerpo, 'cortar': len(cuerpo) - cuerpo.index(sha1(NUEVA)[5:])}
        self.assertGreaterEqual(cuerpo.index(sha1(NUEVA)[5:]) // 38, passwords.PWNED_MIN_LINEAS)
        for caso, kw in casos.items():
            with self.subTest(caso=caso):
                self.responder(**kw)
                self.assertIsNone(passwords.filtrada(NUEVA))

    def test_3d_una_respuesta_gota_a_gota_no_deja_el_hilo_colgado(self):
        self.plazo(0.1)
        api = self.responder(gota=True)
        self.assertIsNone(passwords.filtrada(NUEVA))
        # El hilo corta la lectura a los 2 plazos y libera su lugar en el cupo.
        fin = time.monotonic() + 3
        while time.monotonic() < fin and any(h.name == 'pwned-passwords' for h in threading.enumerate()):
            time.sleep(0.02)
        self.assertFalse(any(h.name == 'pwned-passwords' for h in threading.enumerate()))
        for _ in range(passwords.PWNED_EN_CURSO):
            self.assertTrue(passwords._pwned_cupo.acquire(blocking=False))
        for _ in range(passwords.PWNED_EN_CURSO):
            passwords._pwned_cupo.release()
        # Ronda 1, hallazgo 2: el timeout de cada recv baja a lo que queda del tope de 2 plazos.
        self.assertGreater(len(api.timeouts), 2)
        self.assertLessEqual(max(api.timeouts), 0.1)
        self.assertLess(api.timeouts[-1], api.timeouts[0])

    def test_3f_con_connection_close_o_http_1_0_lee_hasta_el_final(self):
        # Ronda 2, R1: con 'Connection: close' o HTTP/1.0 el último read1 cierra el socket y el settimeout de la
        # vuelta siguiente daba OSError, así que toda revisión daba None. Aquí va el http.client real.
        casos = {'keep-alive': http_(rango(NUEVA)), 'Connection: close': http_(rango(NUEVA), 'Connection: close'),
                 'HTTP/1.0': http_(rango(NUEVA), version='HTTP/1.0')}
        for caso, bytes_ in casos.items():
            with self.subTest(caso=caso):
                self.api = api = Crudo(bytes_)
                with mock.patch.object(passwords.http.client, 'HTTPSConnection', api):
                    self.assertIs(passwords.filtrada(NUEVA), True)
                self.assertEqual(len(api.peticiones), 1)
                self.assertGreater(len(api.timeouts), 2)
                if caso != 'keep-alive':
                    self.assertTrue(api.socket.real_cerrado, 'el socket se cerró al terminar la respuesta')

    def test_3g_encabezados_gota_a_gota_no_dejan_el_hilo_colgado(self):
        # Ronda 2, hallazgo 2 incompleto: getresponse() lee los encabezados con varios recv y cada uno reiniciaba el
        # timeout. Ahora el tope de 2 plazos vale antes de cada recv, también en los encabezados.
        self.plazo(0.1)
        self.api = api = Crudo(gota=True)
        with mock.patch.object(passwords.http.client, 'HTTPSConnection', api):
            self.assertIsNone(passwords.filtrada(NUEVA))
            fin = time.monotonic() + 2
            while time.monotonic() < fin and any(h.name == 'pwned-passwords' for h in threading.enumerate()):
                time.sleep(0.02)
        self.assertFalse(any(h.name == 'pwned-passwords' for h in threading.enumerate()),
                         'el hilo sigue leyendo encabezados después del tope')
        self.assertLessEqual(max(api.timeouts), 0.1)
        self.assertLess(api.timeouts[-1], api.timeouts[0])

    def test_3e_con_el_cupo_lleno_no_consulta_y_sigue_con_la_lista(self):
        self.plazo(0.05)
        api = self.responder(colgar=True)
        for _ in range(passwords.PWNED_EN_CURSO):
            self.assertIsNone(passwords.filtrada(NUEVA))
        self.assertEqual(len(api.peticiones), passwords.PWNED_EN_CURSO)
        inicio = time.monotonic()
        self.assertIsNone(passwords.filtrada(NUEVA))
        self.assertLess(time.monotonic() - inicio, 0.05, 'con el cupo lleno no espera el plazo')
        self.assertEqual(len(api.peticiones), passwords.PWNED_EN_CURSO, 'la quinta no sale')
        self.assertEqual(self.esperar_hilos(), [])
        api.soltar.clear()
        self.api = self.responder(cuerpo=rango(NUEVA))
        self.assertIs(passwords.filtrada(NUEVA), True, 'al soltarse, el cupo vuelve')


class Revisar(Filtradas):
    """Puntos 2 y 4: revisar_nueva junta la lista local y la API, y la variable la prende o la apaga."""

    def test_4_la_variable_solo_prende_con_true(self):
        for valor, prendida in (('', False), ('false', False), ('0', False), ('1', False), ('sí', False),
                                ('true', True), ('TRUE', True), (' True ', True)):
            with self.subTest(valor=valor):
                self.env(PWNED_PASSWORDS_ENABLED=valor)
                self.assertIs(passwords.pwned_prendida(), prendida)
        limpio = {k: v for k, v in os.environ.items() if k != 'PWNED_PASSWORDS_ENABLED'}
        with mock.patch.dict(os.environ, limpio, clear=True):
            self.assertFalse(passwords.pwned_prendida(), 'apagada por omisión')

    def test_4b_apagada_no_consulta(self):
        api = self.responder(cuerpo=rango(NUEVA))
        self.env(PWNED_PASSWORDS_ENABLED='false')
        self.assertEqual(passwords.revisar_nueva(NUEVA), (None, False))
        self.assertEqual(api.peticiones, [])

    def test_4c_la_comun_no_consulta_la_api(self):
        self.assertTrue(passwords.is_common(COMUN))
        api = self.responder(cuerpo=rango(OTRA))
        self.assertEqual(passwords.revisar_nueva(COMUN), ('comun', False))
        self.assertEqual(passwords.revisar_nueva(COMUN.upper()), ('comun', False))
        self.assertEqual(api.peticiones, [])

    def test_4d_filtrada_sin_filtrar_y_sin_respuesta(self):
        self.assertFalse(passwords.is_common(NUEVA))
        self.responder(cuerpo=rango(NUEVA))
        self.assertEqual(passwords.revisar_nueva(NUEVA), ('filtrada', False))
        self.responder(cuerpo=rango(OTRA))
        self.assertEqual(passwords.revisar_nueva(NUEVA), (None, False))
        self.plazo()
        self.responder(colgar=True)
        self.assertEqual(passwords.revisar_nueva(NUEVA), (None, True))

    def test_4e_permitir_se_llama_solo_antes_de_consultar(self):
        api = self.responder(cuerpo=rango(NUEVA))
        llamadas = []

        def permitir(valor):
            return lambda: llamadas.append(valor) or valor
        self.assertEqual(passwords.revisar_nueva(NUEVA, permitir(False)), (None, True))
        self.assertEqual(api.peticiones, [])
        self.assertEqual(passwords.revisar_nueva(NUEVA, permitir(True)), ('filtrada', False))
        self.assertEqual(len(api.peticiones), 1)
        self.assertEqual(passwords.revisar_nueva(COMUN, permitir(True)), ('comun', False))
        self.env(PWNED_PASSWORDS_ENABLED='false')
        self.assertEqual(passwords.revisar_nueva(NUEVA, permitir(True)), (None, False))
        self.assertEqual(llamadas, [False, True])


class BaseCambio:
    """Hace de cirdan.db.transaction para POST /auth/password: la fila de la cuenta tiene `huella` y se anota cada
    UPDATE y cada evento de la bitácora."""

    def __init__(self, huella):
        self.huella = huella
        self.transacciones = 0
        self.updates = []
        self.eventos = []

    @contextmanager
    def transaction(self, org=None):
        self.transacciones += 1
        yield self

    def execute(self, sql, parametros=()):
        if sql.startswith('SELECT password_hash FROM users WHERE id'):
            return mock.Mock(**{'fetchone.return_value': {'password_hash': self.huella}})
        if sql.startswith('UPDATE users SET password_hash'):
            self.updates.append(parametros)
            return mock.Mock(rowcount=1)
        if sql.startswith('DELETE FROM webauthn_credentials'):
            return mock.Mock(**{'fetchall.return_value': []})
        raise AssertionError('consulta no esperada: %s' % sql)

    def audit(self, conn, org, action, *args, **kw):
        # audit(conn, org, action, user_id, ip, entity_type, entity_id, details, ...)
        details = kw.get('details', args[4] if len(args) > 4 else None)
        self.eventos.append((action, details))


class Ruta(Filtradas):
    """Puntos 2 y 3 por POST /api/v1/auth/password, con base y Valkey falsos."""

    def cambiar(self, nueva, consultas=1):
        base = BaseCambio(passwords.hash_password(CLAVE, ALEX))
        sesiones = mock.Mock(MAX_PASSWORD_ATTEMPTS=5, LOCK_SECONDS=900, MAX_PWNED_CHECKS=10,
                             **{'take_password_attempt.return_value': 1, 'take_pwned_check.return_value': consultas})
        sesion = Session(token='CIRDAN_FAKE_sesion', user_id=ALEX, org_id=ORG, role='admin', email='alex@acme-demo.mx')
        with mock.patch.object(routes, 'transaction', base.transaction), \
                mock.patch.object(routes, 'audit', base.audit), \
                mock.patch.object(routes, 'sessions', sesiones), \
                mock.patch.object(routes, 'client_ip', return_value='127.0.0.1'):
            try:
                respuesta = routes.change_password(routes.PasswordIn(current_password=CLAVE, new_password=nueva),
                                                   mock.Mock(), sesion)
            except routes.HTTPException as e:
                respuesta = e
        return respuesta, base, sesiones

    def assert_sin_cambios(self, base, sesiones):
        self.assertEqual((base.transacciones, base.updates, base.eventos), (0, [], []))
        sesiones.take_password_attempt.assert_not_called()
        sesiones.delete_others.assert_not_called()

    def test_2_filtrada_da_400_y_no_cambia_nada(self):
        self.responder(cuerpo=rango(NUEVA))
        respuesta, base, sesiones = self.cambiar(NUEVA)
        self.assertEqual((respuesta.status_code, respuesta.detail), (400, FILTRADA))
        self.assertEqual(routes.PWNED_PASSWORD, FILTRADA)
        self.assert_sin_cambios(base, sesiones)

    def test_2b_la_comun_da_400_sin_consultar_la_api(self):
        api = self.responder(cuerpo=rango(OTRA))
        respuesta, base, sesiones = self.cambiar(COMUN)
        self.assertEqual((respuesta.status_code, respuesta.detail), (400, routes.COMMON_PASSWORD))
        self.assert_sin_cambios(base, sesiones)
        self.assertEqual(api.peticiones, [])

    def test_2c_una_que_no_sale_da_200_y_cambia(self):
        api = self.responder(cuerpo=rango(OTRA))
        respuesta, base, sesiones = self.cambiar(NUEVA)
        self.assertEqual(respuesta, {'passkeys_removed': 0})
        self.assertEqual(len(api.peticiones), 1)
        self.assertEqual(len(base.updates), 1)
        self.assertTrue(passwords.verify_password(base.updates[0][0], NUEVA, ALEX))
        self.assertEqual([e[0] for e in base.eventos], ['auth.password_changed'])

    def test_3_sin_respuesta_cambia_y_deja_el_evento_sin_la_contrasena(self):
        self.plazo()
        self.responder(colgar=True)
        respuesta, base, sesiones = self.cambiar(NUEVA)
        self.assertEqual(respuesta, {'passkeys_removed': 0})
        self.assertEqual(len(base.updates), 1)
        self.assertEqual(base.eventos, [('auth.password_changed', None),
                                        ('auth.pwned_check_unavailable', {'fallback': 'common_list'})])
        self.assert_sin_rastro(json.dumps(base.eventos), NUEVA)

    def test_3b_sin_respuesta_una_comun_sigue_rechazada(self):
        self.plazo()
        self.responder(colgar=True)
        respuesta, base, sesiones = self.cambiar(COMUN)
        self.assertEqual((respuesta.status_code, respuesta.detail), (400, routes.COMMON_PASSWORD))
        self.assert_sin_cambios(base, sesiones)

    def test_4_apagada_no_consulta_y_cambia(self):
        self.env(PWNED_PASSWORDS_ENABLED='false')
        api = self.responder(cuerpo=rango(NUEVA))
        respuesta, base, sesiones = self.cambiar(NUEVA)
        self.assertEqual(respuesta, {'passkeys_removed': 0})
        self.assertEqual(api.peticiones, [])
        self.assertEqual([e[0] for e in base.eventos], ['auth.password_changed'])
        sesiones.take_pwned_check.assert_not_called()

    def test_5_cada_consulta_a_la_api_cuenta_para_el_tope_del_usuario(self):
        # Ronda 1, hallazgo 4: la revisión va antes de gastar un intento, así que lleva su propio tope.
        self.responder(cuerpo=rango(OTRA))
        _, _, sesiones = self.cambiar(NUEVA, consultas=10)
        sesiones.take_pwned_check.assert_called_once_with(ALEX)
        api = self.responder(cuerpo=rango(OTRA))
        _, _, sesiones = self.cambiar(COMUN)
        sesiones.take_pwned_check.assert_not_called()
        self.assertEqual(api.peticiones, [])

    def test_5b_pasado_el_tope_no_consulta_y_sigue_con_la_lista_local(self):
        api = self.responder(cuerpo=rango(NUEVA))
        respuesta, base, _ = self.cambiar(NUEVA, consultas=11)
        self.assertEqual(api.peticiones, [])
        self.assertEqual(respuesta, {'passkeys_removed': 0})
        self.assertEqual(len(base.updates), 1)
        self.assertEqual(base.eventos, [('auth.password_changed', None),
                                        ('auth.pwned_check_unavailable',
                                         {'fallback': 'common_list', 'reason': 'rate_limited'})])
        # Pasado el tope, la común sigue rechazada.
        respuesta, base, _ = self.cambiar(COMUN, consultas=11)
        self.assertEqual((respuesta.status_code, respuesta.detail), (400, routes.COMMON_PASSWORD))
        self.assertEqual(base.eventos, [])

    def test_5c_el_contador_es_por_usuario_y_no_guarda_el_id(self):
        with mock.patch.object(sessions, '_count', return_value=[3]) as contar:
            self.assertEqual(sessions.take_pwned_check(ALEX), 3)
        llave, = contar.call_args.args
        self.assertTrue(llave.startswith('pw:pwned:user:'))
        self.assertNotIn(ALEX, llave)
        self.assertNotEqual(llave, sessions._password_key(ALEX))
        self.assertEqual(sessions.MAX_PWNED_CHECKS, 10)


if __name__ == '__main__':
    import unittest
    unittest.main()

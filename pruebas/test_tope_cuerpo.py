"""Pruebas sin red ni base del tope al cuerpo de las peticiones (RC-298).

Llaman a la app ASGI directo, sin servidor: cada prueba arma el scope y entrega el cuerpo en pedazos, así se ve
cuántos pedazos leyó la API antes de cortar. Sin Valkey ni PostgreSQL: el login normal usa los falsos de
test_login_sin_red.py. Corren dentro del contenedor, porque cirdan.api.main importa fastapi, psycopg y redis:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_tope_cuerpo.py
"""
import asyncio
import contextlib
import json
import unittest
from types import SimpleNamespace
from unittest import mock

from cirdan.api import main
from cirdan.api.main import TOPE_CUERPO, TopeDeCuerpo
from cirdan.auth import routes, sessions
from pruebas.test_login_sin_red import ValkeyConMulti

LOGIN = '/api/v1/auth/login'
PEDAZO = 16 * 1024


def llamar(app, metodo, ruta, pedazos, headers=()):
    """Una petición ASGI con el cuerpo en `pedazos` (bytes). Devuelve el estado, las cabeceras de la respuesta en
    minúsculas, el cuerpo, cuántos pedazos pidió la app y cuántas veces empezó una respuesta."""
    pedazos = list(pedazos)
    leidos, enviados = [0], []

    async def receive():
        if leidos[0] >= len(pedazos):
            # Después del último pedazo, la app que siga esperando ve al cliente irse.
            await asyncio.sleep(0)
            return {'type': 'http.disconnect'}
        leidos[0] += 1
        return {'type': 'http.request', 'body': pedazos[leidos[0] - 1], 'more_body': leidos[0] < len(pedazos)}

    async def send(mensaje):
        enviados.append(mensaje)

    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': metodo, 'scheme': 'http',
             'path': ruta, 'raw_path': ruta.encode(), 'query_string': b'', 'root_path': '',
             'headers': [(k.lower().encode(), v.encode()) for k, v in headers],
             'client': ('127.0.0.1', 50000), 'server': ('127.0.0.1', 8000)}
    asyncio.run(app(scope, receive, send))
    inicios = [m for m in enviados if m['type'] == 'http.response.start']
    cuerpo = b''.join(m.get('body', b'') for m in enviados if m['type'] == 'http.response.body')
    cabeceras = {k.decode().lower(): v.decode() for k, v in inicios[0]['headers']} if inicios else {}
    return SimpleNamespace(status=inicios[0]['status'] if inicios else None, headers=cabeceras, body=cuerpo,
                           leidos=leidos[0], inicios=len(inicios))


def json_login(captcha='CIRDAN_FAKE_captcha'):
    return json.dumps({'email': 'tope@ejemplo.test', 'password': 'CIRDAN_FAKE_contrasena',
                       'captcha': captcha}).encode()


def en_pedazos(datos, tamano=PEDAZO):
    return [datos[i:i + tamano] for i in range(0, len(datos), tamano)] or [b'']


class AppQueLee:
    """App ASGI que junta el cuerpo y responde 200 con su largo, como una ruta que lee todo."""

    def __init__(self):
        self.llamadas = 0

    async def __call__(self, scope, receive, send):
        self.llamadas += 1
        cuerpo = b''
        while True:
            mensaje = await receive()
            if mensaje['type'] != 'http.request':
                break
            cuerpo += mensaje.get('body', b'')
            if not mensaje.get('more_body'):
                break
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': str(len(cuerpo)).encode()})


class ApiReal(unittest.TestCase):
    """Contra cirdan.api.main.app, la misma que sirve uvicorn, en una ruta sin sesión."""

    def setUp(self):
        self.captchas = []

        def verify(payload):
            self.captchas.append(payload)
            return False

        parche = mock.patch.object(routes.captcha, 'verify', verify)
        parche.start()
        self.addCleanup(parche.stop)

    def test_1_content_length_de_mas_da_413_sin_leer_el_cuerpo_ni_entrar_a_la_ruta(self):
        r = llamar(main.app, 'POST', LOGIN, [b'{}'],
                   headers=[('content-type', 'application/json'), ('content-length', str(TOPE_CUERPO + 1))])
        self.assertEqual(r.status, 413)
        self.assertEqual(r.leidos, 0, 'el cuerpo no se lee')
        self.assertEqual(self.captchas, [], 'la ruta de login no se ejecuta')
        self.assertEqual(json.loads(r.body), {'detail': 'El cuerpo de la petición pasa el tope de 64 KB'})
        self.assertEqual(r.headers.get('connection'), 'close')
        # Queda dentro de cabeceras_de_seguridad (RC-283).
        self.assertEqual(r.headers.get('x-frame-options'), 'DENY')
        self.assertEqual(r.headers.get('x-content-type-options'), 'nosniff')

    def test_2_content_length_enorme_o_repetido_tambien_da_413(self):
        for valores in (['9' * 40], ['10', str(TOPE_CUERPO + 1)], [' %d ' % (TOPE_CUERPO * 1000)]):
            with self.subTest(valores=valores):
                r = llamar(main.app, 'POST', LOGIN, [b'{}'],
                           headers=[('content-type', 'application/json')] + [('content-length', v) for v in valores])
                self.assertEqual((r.status, r.leidos), (413, 0))
        self.assertEqual(self.captchas, [])

    def test_3_chunked_que_pasa_el_tope_da_413_sin_juntar_el_cuerpo(self):
        # 1 MB en pedazos de 16 KB, sin Content-Length: corta en el pedazo que pasa los 64 KB.
        r = llamar(main.app, 'POST', LOGIN, en_pedazos(b'x' * (1024 * 1024)),
                   headers=[('content-type', 'application/json'), ('transfer-encoding', 'chunked')])
        self.assertEqual(r.status, 413)
        self.assertEqual(r.leidos, TOPE_CUERPO // PEDAZO + 1, 'lee hasta el pedazo que pasa el tope y para')
        self.assertEqual(r.inicios, 1, 'el 400 de FastAPI no sale antes ni después del 413')
        self.assertEqual(self.captchas, [])
        self.assertEqual(r.headers.get('connection'), 'close')
        self.assertEqual(r.headers.get('x-frame-options'), 'DENY')

    def test_4_un_json_de_login_valido_pero_inflado_pasa_el_tope_y_da_413(self):
        # Un captcha de 70 KB dentro de un JSON bien formado: antes FastAPI lo juntaba entero y luego daba 422.
        cuerpo = json_login(captcha='A' * (70 * 1024))
        for headers in ([('content-length', str(len(cuerpo)))], [('transfer-encoding', 'chunked')]):
            with self.subTest(headers=headers):
                r = llamar(main.app, 'POST', LOGIN, en_pedazos(cuerpo),
                           headers=[('content-type', 'application/json')] + headers)
                self.assertEqual(r.status, 413)
        self.assertEqual(self.captchas, [])

    def test_5_el_tope_vale_tambien_en_otras_rutas_y_metodos(self):
        grande = en_pedazos(b'x' * (TOPE_CUERPO + 1))
        # Las rutas que leen cuerpo, con o sin sesión: FastAPI lee el cuerpo antes de revisar la sesión.
        for metodo, ruta in (('POST', '/api/v1/auth/mfa/verify'), ('POST', '/api/v1/auth/passkeys/login/verify'),
                             ('PUT', '/api/v1/scoring/weights'), ('POST', '/api/v1/api-keys')):
            with self.subTest(metodo=metodo, ruta=ruta, chunked=True):
                r = llamar(main.app, metodo, ruta, grande, headers=[('content-type', 'application/json')])
                self.assertEqual(r.status, 413)
        # Con Content-Length, cualquier ruta, también las que no leen cuerpo y las que no existen.
        for metodo, ruta in (('PUT', '/api/v1/scoring/weights'), ('POST', '/no-existe'), ('GET', '/health')):
            with self.subTest(metodo=metodo, ruta=ruta, chunked=False):
                r = llamar(main.app, metodo, ruta, grande, headers=[('content-length', str(TOPE_CUERPO + 1))])
                self.assertEqual((r.status, r.leidos), (413, 0))

    def test_5b_chunked_en_una_ruta_que_no_lee_el_cuerpo_tambien_da_413(self):
        # /auth/me sin sesión, /health y logout responden sin leer el cuerpo. Con chunked el middleware lee y tira el
        # resto antes de dejar salir la respuesta: al pasar el tope sale el 413 y la conexión se cierra, en vez de que
        # uvicorn siga leyendo un cuerpo sin fin después del 401, 200 o 204.
        @contextlib.contextmanager
        def transaccion(org_id=None):
            yield SimpleNamespace(execute=lambda *a: None)

        chunked = [('transfer-encoding', 'chunked')]
        with mock.patch.object(main, 'transaction', transaccion):
            for metodo, ruta, normal in (('GET', '/api/v1/auth/me', 401), ('GET', '/health', 200),
                                         ('POST', '/api/v1/auth/logout', 204)):
                with self.subTest(ruta=ruta, cuerpo='de más'):
                    r = llamar(main.app, metodo, ruta, en_pedazos(b'x' * (TOPE_CUERPO * 4)), headers=chunked)
                    self.assertEqual((r.status, r.inicios), (413, 1))
                    self.assertEqual(r.leidos, TOPE_CUERPO // PEDAZO + 1, 'lee hasta el pedazo que pasa el tope y para')
                    self.assertEqual(r.headers.get('connection'), 'close')
                    self.assertEqual(r.headers.get('x-frame-options'), 'DENY')
                with self.subTest(ruta=ruta, cuerpo='chico'):
                    # Un cuerpo chunked chico se lee entero y la respuesta de la ruta sale igual, sin cerrar.
                    pedazos = en_pedazos(b'x' * (PEDAZO * 2 + 10))
                    r = llamar(main.app, metodo, ruta, pedazos, headers=chunked)
                    self.assertEqual((r.status, r.leidos), (normal, len(pedazos)))
                    self.assertNotIn('connection', r.headers)
                with self.subTest(ruta=ruta, cuerpo='con Content-Length'):
                    # Con Content-Length dentro del tope el servidor ya lee a lo más lo anunciado: no se toca.
                    r = llamar(main.app, metodo, ruta, [b'x' * 10], headers=[('content-length', '10')])
                    self.assertEqual((r.status, r.leidos), (normal, 0))

    def test_6_login_con_cuerpo_normal_llega_igual_a_la_ruta(self):
        # Con y sin Content-Length el cuerpo llega completo: el captcha que ve la ruta es el que se mandó.
        cuerpo = json_login(captcha='CIRDAN_FAKE_' + 'c' * 4000)
        for headers in ([('content-length', str(len(cuerpo)))], [('transfer-encoding', 'chunked')]):
            with self.subTest(headers=headers):
                self.captchas.clear()
                r = llamar(main.app, 'POST', LOGIN, en_pedazos(cuerpo, 1024),
                           headers=[('content-type', 'application/json')] + headers)
                self.assertEqual(r.status, 400)
                self.assertEqual(json.loads(r.body), {'detail': routes.CAPTCHA_INVALID})
                self.assertEqual(self.captchas, ['CIRDAN_FAKE_' + 'c' * 4000])


class LoginNormal(unittest.TestCase):
    """Un login con contraseña buena y MFA sigue igual con el middleware delante: 200 y su mfa_token."""

    def setUp(self):
        self.valkey = ValkeyConMulti()
        fila = {'organization_id': 'o-1', 'user_id': 'u-1', 'password_hash': 'x', 'mfa_enabled': True}

        @contextlib.contextmanager
        def transaccion(org_id=None):
            yield SimpleNamespace(execute=lambda *a: SimpleNamespace(fetchone=lambda: fila))

        for parche in (mock.patch.object(sessions, '_valkey', lambda: self.valkey),
                       mock.patch.object(routes.captcha, 'verify', lambda _: True),
                       mock.patch.object(routes, 'transaction', transaccion),
                       mock.patch.object(routes.passwords, 'verify_password', lambda *_: True),
                       mock.patch.object(routes.passwords, 'needs_rehash', lambda *_: False)):
            parche.start()
            self.addCleanup(parche.stop)

    def test_1_contrasena_buena_con_mfa_da_200_y_el_token(self):
        cuerpo = json_login()
        for headers in ([('content-length', str(len(cuerpo)))], [('transfer-encoding', 'chunked')]):
            with self.subTest(headers=headers):
                r = llamar(main.app, 'POST', LOGIN, en_pedazos(cuerpo, 32),
                           headers=[('content-type', 'application/json')] + headers)
                self.assertEqual(r.status, 200, r.body)
                salida = json.loads(r.body)
                self.assertIs(salida['mfa_required'], True)
                self.assertGreaterEqual(len(salida['mfa_token']), 10)


class Middleware(unittest.TestCase):
    """TopeDeCuerpo con una app de prueba: los bordes del tope."""

    def test_1_justo_el_tope_pasa_y_uno_mas_no(self):
        for largo, esperado in ((TOPE_CUERPO, 200), (TOPE_CUERPO + 1, 413)):
            for con_largo in (True, False):
                with self.subTest(largo=largo, content_length=con_largo):
                    app = AppQueLee()
                    headers = [('content-length', str(largo))] if con_largo else []
                    r = llamar(TopeDeCuerpo(app), 'POST', '/', en_pedazos(b'x' * largo), headers=headers)
                    self.assertEqual(r.status, esperado)
                    if esperado == 200:
                        self.assertEqual(r.body, str(largo).encode())
                    self.assertEqual(app.llamadas, 0 if con_largo and esperado == 413 else 1)

    def test_2_mas_bytes_que_los_anunciados_tambien_corta(self):
        # Content-Length chico y cuerpo grande: el servidor no lo deja pasar, pero el conteo no depende de eso.
        r = llamar(TopeDeCuerpo(AppQueLee()), 'POST', '/', en_pedazos(b'x' * (TOPE_CUERPO * 2)),
                   headers=[('content-length', '10')])
        self.assertEqual((r.status, r.inicios), (413, 1))

    def test_3_content_length_que_no_es_numero_no_se_toma_como_tope(self):
        r = llamar(TopeDeCuerpo(AppQueLee()), 'POST', '/', [b'hola'], headers=[('content-length', 'abc')])
        self.assertEqual((r.status, r.body), (200, b'4'))

    def test_4_la_app_que_atrapa_el_corte_y_responde_otra_cosa_igual_da_413(self):
        async def app(scope, receive, send):
            try:
                while (await receive()).get('more_body'):
                    pass
            except Exception:
                pass
            await send({'type': 'http.response.start', 'status': 400, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'otra cosa'})

        r = llamar(TopeDeCuerpo(app), 'POST', '/', en_pedazos(b'x' * (TOPE_CUERPO + PEDAZO)))
        self.assertEqual((r.status, r.inicios), (413, 1))

    def test_5_si_la_respuesta_ya_empezo_no_la_cambia_y_corta(self):
        async def app(scope, receive, send):
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            while (await receive()).get('more_body'):
                pass

        with self.assertRaises(main.CuerpoDemasiadoGrande):
            llamar(TopeDeCuerpo(app), 'POST', '/', en_pedazos(b'x' * (TOPE_CUERPO + PEDAZO)))

    def test_5c_chunked_leido_a_medias_se_termina_de_contar_antes_de_responder(self):
        # La app lee un pedazo y responde: con chunked el resto se cuenta antes de que salga su respuesta.
        async def app(scope, receive, send):
            await receive()
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'listo'})

        chunked = [('transfer-encoding', 'chunked')]
        for largo, esperado in ((TOPE_CUERPO, 200), (TOPE_CUERPO + 1, 413)):
            with self.subTest(largo=largo):
                pedazos = en_pedazos(b'x' * largo)
                r = llamar(TopeDeCuerpo(app), 'POST', '/', pedazos, headers=chunked)
                self.assertEqual((r.status, r.inicios, r.leidos), (esperado, 1, len(pedazos)))

    def test_5d_si_el_cliente_se_va_a_media_lectura_sale_la_respuesta_de_la_app(self):
        # El receive de llamar() da http.disconnect después del último pedazo, aunque diga more_body: se deja de leer.
        async def app(scope, receive, send):
            await send({'type': 'http.response.start', 'status': 204, 'headers': []})
            await send({'type': 'http.response.body', 'body': b''})

        async def corta(scope, receive, send):
            async def receive_sin_fin():
                mensaje = await receive()
                if mensaje['type'] == 'http.request':
                    mensaje = dict(mensaje, more_body=True)
                return mensaje
            await TopeDeCuerpo(app)(scope, receive_sin_fin, send)

        r = llamar(corta, 'POST', '/', [b'x' * 10], headers=[('transfer-encoding', 'chunked')])
        self.assertEqual((r.status, r.leidos), (204, 1))

    def test_6_lifespan_y_websocket_pasan_sin_tocar(self):
        vistos = []

        async def app(scope, receive, send):
            vistos.append((scope['type'], receive, send))

        async def receive():
            return {}

        async def send(_):
            return None

        for tipo in ('lifespan', 'websocket'):
            asyncio.run(TopeDeCuerpo(app)({'type': tipo}, receive, send))
        self.assertEqual(vistos, [('lifespan', receive, send), ('websocket', receive, send)])

    def test_7_main_lo_pone_dentro_de_los_middlewares_de_seguridad(self):
        clases = [m.cls for m in main.app.user_middleware]
        self.assertIn(TopeDeCuerpo, clases)
        self.assertEqual(clases[-1], TopeDeCuerpo, 'el último de la lista es el más de adentro')


if __name__ == '__main__':
    unittest.main()

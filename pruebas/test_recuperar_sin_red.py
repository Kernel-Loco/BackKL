"""Recuperar la contraseña con un enlace (RC-335) sin red: los correos, los tokens y límites en Valkey y las rutas con
la base y Resend falsos. Corren dentro del contenedor, porque cirdan.auth.routes importa fastapi, psycopg y redis, y
usan el Valkey del compose para los scripts de los tokens:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_recuperar_sin_red.py

El Hecho cuando de punta a punta (HTTP, base y Resend simulado) está en pruebas/test_recuperar.py.
"""
import contextlib
import json
import logging
import os
import threading
import unittest
import uuid
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException, Response

from cirdan import correo
from cirdan.auth import routes, sessions
from cirdan.auth.demo import HASH_DE_RELLENO

ENLACE = 'http://portal.prueba/forgot-password/reset#t=TOKEN-DE-PRUEBA-que-no-va-al-log'
DESTINO = 'alguien@ejemplo.com'


def _al_azar():
    return uuid.uuid4().hex


@contextlib.contextmanager
def entorno(**variables):
    with mock.patch.dict(os.environ, {k: v for k, v in variables.items() if v is not None}):
        for k, v in variables.items():
            if v is None:
                os.environ.pop(k, None)
        yield


class Correo(unittest.TestCase):
    """cirdan/correo.py: el enlace de recuperación y el aviso, sin datos de la cuenta y sin el token en el log."""

    def test_1_el_enlace_solo_lleva_el_enlace_y_cuanto_dura(self):
        asunto, texto, pagina = correo.cuerpo_recuperar(ENLACE, 30)
        self.assertEqual(asunto, 'Elige una contraseña nueva para LowTide')
        for parte in (texto, pagina):
            self.assertIn('30 minutos', parte)
            self.assertNotIn(DESTINO, parte)
        self.assertIn(ENLACE, texto)
        self.assertIn('href="%s"' % ENLACE, pagina)
        self.assertIn('&quot;', correo.cuerpo_recuperar('http://x/"><script>', 30)[2])

    def test_2_el_aviso_no_lleva_enlaces(self):
        asunto, texto, pagina = correo.cuerpo_aviso()
        self.assertEqual(asunto, 'Tu contraseña de LowTide cambió')
        self.assertNotIn('http', texto + pagina)
        self.assertNotIn('<a ', pagina)

    def test_3_sin_llave_no_sale_nada_y_el_log_no_lleva_el_correo(self):
        llamadas = []
        with entorno(CORREO_API_KEY=None), mock.patch.object(correo, '_abrir', lambda req: llamadas.append(req)), \
                self.assertLogs('cirdan.correo', 'WARNING') as logs:
            self.assertEqual(correo.enviar_recuperacion(DESTINO, ENLACE, 30), 'sin_llave')
            self.assertEqual(correo.enviar_aviso_cambio(DESTINO), 'sin_llave')
        self.assertEqual(llamadas, [])
        texto = '\n'.join(logs.output)
        self.assertNotIn(DESTINO, texto)
        self.assertNotIn('TOKEN-DE-PRUEBA', texto)

    def test_4_aceptado_va_a_la_url_con_la_llave(self):
        vistas = []
        with entorno(CORREO_API_KEY='llave-de-prueba', CORREO_API_URL='http://correo-falso:8025/emails',
                     CORREO_REMITENTE=None), mock.patch.object(correo, '_abrir', lambda req: vistas.append(req) or 200):
            self.assertIsNone(correo.enviar_recuperacion(DESTINO, ENLACE, 30))
            self.assertIsNone(correo.enviar_aviso_cambio(DESTINO))
        self.assertEqual([json.loads(r.data)['subject'] for r in vistas],
                         ['Elige una contraseña nueva para LowTide', 'Tu contraseña de LowTide cambió'])
        self.assertEqual({r.get_header('Authorization') for r in vistas}, {'Bearer llave-de-prueba'})


class TokensEnValkey(unittest.TestCase):
    """cirdan/auth/sessions.py contra el Valkey del compose: hash, 30 min, una vez, el nuevo anula y los límites."""

    def datos(self):
        # Sin el correo: el canje lo toma de la base (H5 de la revisión).
        return {'user_id': str(uuid.uuid4()), 'org_id': str(uuid.uuid4()), 'tag': _al_azar()}

    def test_5_token_de_256_bits_guardado_solo_por_su_hash_y_30_minutos(self):
        datos = self.datos()
        token = sessions.create_reset(datos)
        self.assertGreaterEqual(len(token), 43)
        valkey = sessions._valkey()
        llave = 'pwreset:' + sessions._digest(token)
        self.assertTrue(valkey.exists(llave))
        self.assertIsNone(valkey.get('pwreset:' + token))
        self.assertNotIn(token, valkey.get(llave))
        self.assertTrue(sessions.RESET_SECONDS - 5 <= valkey.ttl(llave) <= sessions.RESET_SECONDS)
        self.assertEqual(sessions.RESET_SECONDS, 30 * 60)
        self.assertEqual(sessions.take_reset(token), datos)
        self.assertIsNone(sessions.take_reset(token))
        self.assertIsNone(valkey.get('pwreset-user:' + sessions._digest(datos['user_id'])))

    def test_6_dos_canjes_a_la_vez_solo_uno_pasa(self):
        token = sessions.create_reset(self.datos())
        resultados, salida = [], threading.Barrier(8)

        def canjear():
            salida.wait()
            resultados.append(sessions.take_reset(token))

        hilos = [threading.Thread(target=canjear) for _ in range(8)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        self.assertEqual(sum(r is not None for r in resultados), 1)

    def test_7_pedir_otro_anula_el_anterior_y_no_toca_el_enlace_para_entrar(self):
        datos = self.datos()
        entrar = sessions.create_link(datos)
        viejo = sessions.create_reset(datos)
        sessions.activate_reset(datos['user_id'], viejo)
        nuevo = sessions.create_reset(datos)
        # El nuevo todavía no salió: el anterior sigue vivo (H4 de la revisión).
        self.assertTrue(sessions._valkey().exists('pwreset:' + sessions._digest(viejo)))
        sessions.activate_reset(datos['user_id'], nuevo)
        self.assertIsNone(sessions.take_reset(viejo))
        self.assertEqual(sessions.take_reset(nuevo), datos)
        self.assertIsNone(sessions.take_reset(entrar))   # los tokens de RC-63 no sirven aquí
        self.assertEqual(sessions.take_link(entrar), datos)   # ni se anulan

    def test_7b_si_el_nuevo_no_sale_el_anterior_sigue_sirviendo(self):
        # H4: pedir otro con Resend caído no deja la cuenta sin ningún enlace válido.
        datos = self.datos()
        viejo = sessions.create_reset(datos)
        sessions.activate_reset(datos['user_id'], viejo)
        nuevo = sessions.create_reset(datos)
        sessions.delete_reset(nuevo)   # lo que hace _send_reset si el envío falla
        self.assertIsNone(sessions.take_reset(nuevo))
        self.assertEqual(sessions.take_reset(viejo), datos)

    def test_7c_activar_un_token_ya_canjeado_no_anula_nada(self):
        datos = self.datos()
        viejo = sessions.create_reset(datos)
        sessions.activate_reset(datos['user_id'], viejo)
        nuevo = sessions.create_reset(datos)
        self.assertEqual(sessions.take_reset(nuevo), datos)
        sessions.activate_reset(datos['user_id'], nuevo)
        self.assertTrue(sessions._valkey().exists('pwreset:' + sessions._digest(viejo)))
        sessions.delete_reset(viejo)

    def test_8_tres_por_correo_y_veinte_por_ip_en_una_hora(self):
        ip = '203.0.113.%d' % (uuid.uuid4().int % 250)
        valkey = sessions._valkey()
        valkey.delete('pwreset:req:ip:' + ip)
        email = _al_azar() + '@ejemplo.com'
        try:
            self.assertEqual([sessions.take_reset_request(email, ip) for _ in range(4)], [True, True, True, False])
            self.assertTrue(15 * 60 < valkey.ttl('pwreset:req:email:' + sessions._digest(email)) <= 60 * 60)
            otros = [sessions.take_reset_request(_al_azar() + '@ejemplo.com', ip) for _ in range(18)]
            self.assertEqual(otros, [True] * 17 + [False])   # 3 + 17 = 20 por la IP
        finally:
            valkey.delete('pwreset:req:ip:' + ip)

    def test_9_entrar_y_recuperar_comparten_el_tope_de_la_cuenta_y_el_aviso_va_aparte(self):
        # H1 de la revisión: separados, cada correo conocido gastaba el doble del día.
        dia = 'prueba-' + _al_azar()
        cuenta = uuid.uuid4()
        try:
            tope = sessions.MAX_LINKS_USER_DAY
            self.assertEqual([sessions.reserve_link_send(80, cuenta, dia) for _ in range(tope - 1)][-1], tope - 1)
            self.assertEqual(sessions.reserve_link_send(80, cuenta, dia, tipo='reset'), tope)
            self.assertEqual(sessions.reserve_link_send(80, cuenta, dia, tipo='reset'), -1)
            self.assertEqual(sessions.reserve_link_send(80, cuenta, dia), -1)
            self.assertEqual(sessions.reserve_link_send(80, cuenta, dia, tipo='aviso'), tope + 1)
            self.assertEqual(sessions._valkey().get('link:day:' + dia), str(tope + 1))   # un solo cupo de Resend
            with self.assertRaises(ValueError):
                sessions.reserve_link_send(80, cuenta, dia, tipo='otro')
        finally:
            for llave in sessions._valkey().scan_iter('link:day:' + dia + '*'):
                sessions._valkey().delete(llave)

    def test_9b_el_aviso_sale_con_el_dia_agotado_hasta_la_reserva(self):
        dia = 'prueba-' + _al_azar()
        try:
            self.assertEqual(sessions.reserve_link_send(1, uuid.uuid4(), dia, tipo='reset'), 1)
            self.assertEqual(sessions.reserve_link_send(1, uuid.uuid4(), dia), 0)   # el día ya llegó
            avisos = [sessions.reserve_link_send(1, uuid.uuid4(), dia, tipo='aviso')
                      for _ in range(sessions.AVISO_RESERVA + 1)]
            self.assertEqual(avisos, list(range(2, sessions.AVISO_RESERVA + 2)) + [0])
            self.assertEqual(sessions.reserve_link_send(0, uuid.uuid4(), dia, tipo='aviso'), 0)   # tope 0: nada sale
        finally:
            for llave in sessions._valkey().scan_iter('link:day:' + dia + '*'):
                sessions._valkey().delete(llave)


class Rutas(unittest.TestCase):
    """cirdan/auth/routes.py sin base ni Resend: la respuesta, el envío después del 202 y el canje."""

    def request(self):
        return SimpleNamespace(client=SimpleNamespace(host='198.51.100.7'), headers={})

    def test_10_misma_respuesta_y_el_envio_va_despues(self):
        with mock.patch.object(routes.captcha, 'verify', return_value=True):
            respuestas = [routes.request_password_reset(routes.PasswordResetIn(email=e, captcha='x'), self.request())
                          for e in ('Alguien@Ejemplo.com ', 'nadie@ejemplo.com')]
        self.assertEqual({(r.status_code, r.body) for r in respuestas}, {(202, respuestas[0].body)})
        self.assertEqual(json.loads(respuestas[0].body)['detail'], routes.RESET_SENT)
        self.assertEqual(respuestas[0].headers['cache-control'], 'no-store')
        self.assertIs(respuestas[0].background.func, routes._send_reset)
        self.assertEqual(respuestas[0].background.args, ('alguien@ejemplo.com', '198.51.100.7'))

    def test_11_sin_captcha_400_antes_de_todo(self):
        with mock.patch.object(routes.captcha, 'verify', return_value=False), \
                mock.patch.object(routes, '_send_reset') as enviar:
            with self.assertRaises(HTTPException) as e:
                routes.request_password_reset(routes.PasswordResetIn(email='a@b.c'), self.request())
        self.assertEqual(e.exception.status_code, 400)
        enviar.assert_not_called()

    @contextlib.contextmanager
    def falsos(self, fila=None, limite=True, tope=1, motivo=None, token=None):
        """La base, la bitácora, Valkey y Resend falsos. Devuelve lo que se llamó."""
        r = SimpleNamespace(bitacora=[], enviados=[], borrados=[], reservas=[], sql=[], creados=[], activados=[])
        conn = mock.MagicMock()

        def ejecutar(sql, params=None):
            r.sql.append(sql)
            return mock.MagicMock(**{'fetchone.return_value': fila, 'fetchall.return_value': []})
        conn.execute.side_effect = ejecutar

        @contextlib.contextmanager
        def transaccion(org=None):
            yield conn

        with mock.patch.object(routes, 'transaction', transaccion), \
                mock.patch.object(routes, 'audit', lambda *a: r.bitacora.append(a)), \
                mock.patch.object(routes.sessions, 'take_reset_request', return_value=limite), \
                mock.patch.object(routes.sessions, 'reserve_link_send', lambda *a, **k: r.reservas.append(k) or tope), \
                mock.patch.object(routes.sessions, 'create_reset', lambda d: r.creados.append(d) or 'TOKEN-DE-PRUEBA'), \
                mock.patch.object(routes.sessions, 'activate_reset', lambda *a: r.activados.append(a)), \
                mock.patch.object(routes.sessions, 'delete_reset', lambda t: r.borrados.append(t)), \
                mock.patch.object(routes.sessions, 'take_reset', return_value=token), \
                mock.patch.object(routes.correo, 'enviar_recuperacion', lambda *a: r.enviados.append(a) or motivo), \
                entorno(PORTAL_URL='https://lowtidesec.com/', ENLACE_TOPE_DIARIO='80'):
            yield r

    def enviar(self, **kw):
        with self.falsos(**kw) as r, self.assertLogs('cirdan.auth.routes', 'WARNING') as logs:
            logging.getLogger('cirdan.auth.routes').warning('marca')  # assertLogs pide al menos una línea
            routes._send_reset('alguien@tec.mx', '198.51.100.7')
        r.log = '\n'.join(logs.output)
        self.assertNotIn('alguien@tec.mx', r.log)
        self.assertNotIn('TOKEN-DE-PRUEBA', r.log)
        return r

    FILA = {'organization_id': uuid.UUID(int=1), 'user_id': uuid.UUID(int=2), 'password_hash': 'lt1$otra'}
    PENDIENTE = {'user_id': str(uuid.UUID(int=2)), 'org_id': str(uuid.UUID(int=1)),
                 'tag': sessions.password_tag('lt1$otra')}
    BUENA = {'email': 'A@tec.mx', 'demo_off': False, 'password_hash': 'lt1$otra'}

    def test_12_cuenta_que_existe_recibe_el_enlace_al_portal(self):
        r = self.enviar(fila=self.FILA)
        (destino, enlace, minutos), = r.enviados
        self.assertEqual((destino, enlace, minutos),
                         ('alguien@tec.mx', 'https://lowtidesec.com/forgot-password/reset#t=TOKEN-DE-PRUEBA', 30))
        self.assertEqual(r.reservas, [{'tipo': 'reset'}])
        (_, _, accion, *_, detalle), = r.bitacora
        self.assertEqual((accion, detalle), ('auth.password_reset_requested', {'expires_minutes': 30}))
        # En Valkey sin el correo (H5) y con la marca de la huella (H2). Anula el anterior solo porque salió (H4).
        self.assertEqual(r.creados, [{'user_id': str(self.FILA['user_id']), 'org_id': str(self.FILA['organization_id']),
                                      'tag': sessions.password_tag(self.FILA['password_hash'])}])
        self.assertEqual(r.activados, [(str(self.FILA['user_id']), 'TOKEN-DE-PRUEBA')])

    def test_13_sin_llave_responde_igual_y_deja_un_evento(self):
        # Punto 4: sin CORREO_API_KEY el token no queda vivo y la bitácora dice por qué.
        r = self.enviar(fila=self.FILA, motivo='sin_llave')
        self.assertEqual(r.borrados, ['TOKEN-DE-PRUEBA'])
        self.assertEqual(r.activados, [])   # el anterior sigue sirviendo (H4)
        (_, _, accion, *_, detalle), = r.bitacora
        self.assertEqual((accion, detalle), ('auth.password_reset_send_failed', {'reason': 'sin_llave'}))

    def test_14_correo_que_no_existe_limite_y_demo_apagada_no_envian_ni_escriben(self):
        for kw in ({'fila': None}, {'fila': self.FILA, 'limite': False},
                   {'fila': dict(self.FILA, password_hash=HASH_DE_RELLENO)}):
            with self.subTest(kw=sorted(kw)):
                r = self.enviar(**kw)
                self.assertEqual((r.enviados, r.bitacora, r.reservas), ([], [], []))

    def test_15_topes_del_dia_no_envian_y_queda_el_motivo(self):
        for tope, motivo in ((0, 'tope_diario'), (-1, 'tope_cuenta')):
            with self.subTest(motivo=motivo):
                r = self.enviar(fila=self.FILA, tope=tope)
                self.assertEqual(r.enviados, [])
                (_, _, accion, *_, detalle), = r.bitacora
                self.assertEqual((accion, detalle), ('auth.password_reset_send_failed', {'reason': motivo}))

    def test_16_token_que_no_sirve_400_sin_tocar_la_base(self):
        with self.falsos(token=None) as r, self.assertRaises(HTTPException) as e:
            routes.confirm_password_reset(routes.PasswordResetConfirmIn(token='x' * 43, new_password='a'), self.request())
        self.assertEqual((e.exception.status_code, e.exception.detail), (400, routes.RESET_INVALID))
        self.assertEqual((r.sql, r.bitacora), ([], []))

    def test_17_el_token_se_gasta_antes_de_revisar_la_contrasena(self):
        pendiente = self.PENDIENTE
        for nueva, razon in (('corta', 'length'), ('x' * 129, 'length'), ('1qaz2wsx3edc', 'common')):
            with self.subTest(razon=razon, largo=len(nueva)), self.falsos(token=pendiente) as r:
                with mock.patch.object(routes.sessions, 'delete_others') as cerrar, \
                        self.assertRaises(HTTPException) as e:
                    routes.confirm_password_reset(routes.PasswordResetConfirmIn(token='x' * 43, new_password=nueva),
                                                  self.request())
                self.assertEqual(e.exception.status_code, 400)
                self.assertTrue(e.exception.detail.endswith(routes.RESET_AGAIN))
                (_, _, accion, *_, detalle), = r.bitacora
                self.assertEqual((accion, detalle), ('auth.password_reset_rejected', {'reason': razon}))
                self.assertFalse(any('UPDATE users' in s for s in r.sql))
                cerrar.assert_not_called()

    def test_17b_vacia_o_enorme_tambien_gasta_el_token(self):
        # H9 de la revisión: el modelo ya no corta con 422 antes de gastar el token.
        for nueva in ('', 'x' * 2000):
            with self.subTest(largo=len(nueva)), self.falsos(token=self.PENDIENTE) as r, \
                    mock.patch.object(routes.sessions, 'take_reset', return_value=self.PENDIENTE) as gastar, \
                    self.assertRaises(HTTPException) as e:
                routes.confirm_password_reset(routes.PasswordResetConfirmIn(token='x' * 43, new_password=nueva),
                                              self.request())
            gastar.assert_called_once_with('x' * 43)
            self.assertEqual((e.exception.status_code, e.exception.detail), (400, routes.RESET_LENGTH + routes.RESET_AGAIN))
            self.assertEqual([a[-1] for a in r.bitacora], [{'reason': 'length'}])

    def test_18_cuenta_desactivada_o_demo_apagada_no_cambia(self):
        pendiente = self.PENDIENTE
        for fila, razon in ((None, 'inactive'), ({'email': 'a@tec.mx', 'demo_off': True}, 'demo_off'),
                            # H2: la contraseña cambió (por /password u otro enlace) después de pedir este.
                            (dict(self.BUENA, password_hash='lt1$la-de-ahora'), 'password_changed')):
            with self.subTest(razon=razon), self.falsos(token=pendiente, fila=fila) as r, \
                    mock.patch.object(routes.sessions, 'delete_others') as cerrar, \
                    self.assertRaises(HTTPException) as e:
                routes.confirm_password_reset(
                    routes.PasswordResetConfirmIn(token='x' * 43, new_password='Marea-Baja-Recupera-2026'),
                    self.request())
            self.assertEqual((e.exception.status_code, e.exception.detail), (400, routes.RESET_INVALID))
            self.assertFalse(any('UPDATE users' in s for s in r.sql))
            cerrar.assert_not_called()
            (_, _, accion, *_, detalle), = r.bitacora
            self.assertEqual((accion, detalle), ('auth.password_reset_rejected', {'reason': razon}))

    def test_19_cambio_bueno_cierra_todas_las_sesiones_y_avisa_despues(self):
        pendiente = self.PENDIENTE
        with self.falsos(token=pendiente, fila=self.BUENA) as r, \
                mock.patch.object(routes.sessions, 'delete_others') as cerrar:
            respuesta = routes.confirm_password_reset(
                routes.PasswordResetConfirmIn(token='x' * 43, new_password='Marea-Baja-Recupera-2026'), self.request())
        self.assertEqual(respuesta.status_code, 200)
        cerrar.assert_called_once_with(pendiente['user_id'], None)   # ninguna sesión se queda
        self.assertTrue(any('UPDATE users SET password_hash' in s for s in r.sql))
        self.assertFalse(any('totp' in s.lower() for s in r.sql if 'UPDATE' in s))   # el MFA no se toca
        self.assertEqual([a[2] for a in r.bitacora], ['auth.password_reset'])
        self.assertIs(respuesta.background.func, routes._after_reset)
        self.assertEqual(respuesta.background.args, (pendiente['user_id'], pendiente['org_id'], 'a@tec.mx',
                                                     '198.51.100.7'))
        # H8: la cookie de este navegador se borra, así /login muestra el aviso en vez de rebotar a /dashboard.
        cookie = respuesta.headers['set-cookie']
        self.assertTrue(cookie.startswith(routes.COOKIE + '='))
        self.assertIn('Max-Age=0', cookie)


class Carreras(unittest.TestCase):
    """H6 y H7 de la revisión: lo que se abrió con la contraseña anterior no crea una sesión después del cambio."""
    CLAVE = 'Marea-Baja-Anterior-2026'
    USER, ORG = str(uuid.UUID(int=2)), str(uuid.UUID(int=1))

    @staticmethod
    def request():
        return SimpleNamespace(client=SimpleNamespace(host='198.51.100.7'), headers={})

    @contextlib.contextmanager
    def base(self, filas):
        """Cada execute() devuelve la siguiente fila de `filas`; deja lo que se pidió en `sql`."""
        sql, pendientes = [], list(filas)
        conn = mock.MagicMock()

        def ejecutar(consulta, params=None):
            sql.append(consulta)
            return mock.MagicMock(**{'fetchone.return_value': pendientes.pop(0) if pendientes else None})
        conn.execute.side_effect = ejecutar

        @contextlib.contextmanager
        def transaccion(org=None):
            yield conn
        with mock.patch.object(routes, 'transaction', transaccion), mock.patch.object(routes, 'audit'):
            yield sql

    def login(self, huella_al_bloquear):
        from cirdan.auth import passwords
        antes = passwords.hash_password(self.CLAVE, self.USER)
        encontrada = {'user_id': self.USER, 'organization_id': self.ORG, 'password_hash': antes, 'mfa_enabled': False}
        # analyst: desde RC-5 un Admin sin TOTP recibe 403 sin sesión, y estas pruebas son de la huella, no del rol.
        bloqueada = {'role': 'analyst', 'password_hash': huella_al_bloquear(antes), 'mfa_enabled': False}
        with self.base([encontrada, bloqueada, {'required': False}]), \
                mock.patch.object(routes.captcha, 'verify', return_value=True), \
                mock.patch.object(routes.sessions, 'take_login_attempt', return_value=[1, 2]), \
                mock.patch.object(routes.sessions, 'refund_login_attempt'), \
                mock.patch.object(routes.sessions, 'register_fail') as fallo, \
                mock.patch.object(routes.sessions, 'clear_fails'), \
                mock.patch.object(routes, '_start_session', return_value={'id': self.USER}) as sesion:
            respuesta = routes.login(routes.LoginIn(email='a@tec.mx', password=self.CLAVE), self.request(), Response())
        return respuesta, sesion, fallo

    def test_20_login_con_la_anterior_que_se_cruza_con_el_cambio_no_crea_sesion(self):
        from cirdan.auth import passwords
        respuesta, sesion, fallo = self.login(lambda _: passwords.hash_password('Marea-Baja-Nueva-2026', self.USER))
        self.assertEqual(respuesta.status_code, 401)
        sesion.assert_not_called()
        fallo.assert_called_once_with('a@tec.mx', '198.51.100.7')

    def test_20b_si_la_huella_cambio_pero_abre_con_la_misma_entra(self):
        # Un login en paralelo de la misma cuenta que la volvió a cifrar (RC-330): misma contraseña, otra huella.
        from cirdan.auth import passwords
        respuesta, sesion, fallo = self.login(lambda _: passwords.hash_password(self.CLAVE, self.USER))
        self.assertEqual(respuesta, {'mfa_required': False, 'user': {'id': self.USER}})
        fallo.assert_not_called()

    def test_20c_misma_huella_entra_sin_revisar_otra_vez(self):
        respuesta, sesion, fallo = self.login(lambda antes: antes)
        self.assertEqual(respuesta['mfa_required'], False)
        sesion.assert_called_once()

    def test_21_mfa_token_de_antes_del_cambio_ya_no_sirve(self):
        pendiente = {'user_id': self.USER, 'org_id': self.ORG, 'email': 'a@tec.mx', 'tag': sessions.password_tag('lt1$antes')}
        for marca in (pendiente, {k: v for k, v in pendiente.items() if k != 'tag'}):
            fila = {'email': 'a@tec.mx', 'role': 'admin', 'password_hash': 'lt1$despues', 'totp_secret_enc': b'x',
                    'last_totp_step': None}
            with self.subTest(con_marca='tag' in marca), self.base([fila]) as sql, \
                    mock.patch.object(routes.sessions, 'take_mfa', return_value=dict(marca)), \
                    mock.patch.object(routes.sessions, 'take_mfa_attempt', return_value=True), \
                    mock.patch.object(routes.sessions, 'delete_mfa') as borrar, \
                    mock.patch.object(routes, '_start_session') as sesion, \
                    self.assertRaises(HTTPException) as e:
                routes.verify_mfa(routes.MfaIn(mfa_token='t' * 20, code='123456'), self.request(), Response())
            self.assertEqual((e.exception.status_code, e.exception.detail), (401, routes.MFA_EXPIRED))
            borrar.assert_called_once_with('t' * 20)
            sesion.assert_not_called()
            if 'tag' in marca:
                self.assertIn('FOR NO KEY UPDATE', sql[0])

    def test_22_enlace_para_entrar_de_antes_del_cambio_ya_no_sirve(self):
        bitacora = []
        fila = {'role': 'admin', 'email': 'a@tec.mx', 'mfa_enabled': False, 'demo_off': False,
                'password_hash': 'lt1$despues'}
        pendiente = {'user_id': self.USER, 'org_id': self.ORG, 'email': 'a@tec.mx', 'tag': sessions.password_tag('lt1$antes')}
        with self.base([fila]), mock.patch.object(routes, 'audit', lambda *a: bitacora.append(a)), \
                mock.patch.object(routes.sessions, 'take_link', return_value=pendiente), \
                mock.patch.object(routes, '_start_session') as sesion, \
                self.assertRaises(HTTPException) as e:
            routes.verify_link(routes.LinkVerifyIn(token='x' * 43), self.request(), Response())
        self.assertEqual((e.exception.status_code, e.exception.detail), (401, routes.LINK_INVALID))
        sesion.assert_not_called()
        self.assertEqual((bitacora[0][2], bitacora[0][-1]), ('auth.link_rejected', {'reason': 'password_changed'}))


if __name__ == '__main__':
    unittest.main(verbosity=2)

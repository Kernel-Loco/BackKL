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

from fastapi import HTTPException

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
        return {'user_id': str(uuid.uuid4()), 'org_id': str(uuid.uuid4()), 'email': _al_azar() + '@ejemplo.com'}

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
        viejo, nuevo = sessions.create_reset(datos), sessions.create_reset(datos)
        self.assertIsNone(sessions.take_reset(viejo))
        sessions.delete_reset(nuevo)
        self.assertIsNone(sessions.take_reset(nuevo))
        self.assertIsNone(sessions.take_reset(entrar))   # los tokens de RC-63 no sirven aquí
        self.assertEqual(sessions.take_link(entrar), datos)   # ni se anulan

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

    def test_9_tope_por_cuenta_aparte_del_enlace_para_entrar(self):
        dia = 'prueba-' + _al_azar()
        cuenta = uuid.uuid4()
        try:
            tope = sessions.MAX_LINKS_USER_DAY
            self.assertEqual([sessions.reserve_link_send(80, cuenta, dia) for _ in range(tope + 1)][-1], -1)
            self.assertEqual(sessions.reserve_link_send(80, cuenta, dia, tipo='reset'), tope + 1)
            self.assertEqual(sessions.reserve_link_send(80, cuenta, dia, tipo='aviso'), tope + 2)
            self.assertEqual(sessions._valkey().get('link:day:' + dia), str(tope + 2))   # un solo cupo de Resend
            with self.assertRaises(ValueError):
                sessions.reserve_link_send(80, cuenta, dia, tipo='otro')
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
        r = SimpleNamespace(bitacora=[], enviados=[], borrados=[], reservas=[], sql=[])
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
                mock.patch.object(routes.sessions, 'create_reset', return_value='TOKEN-DE-PRUEBA'), \
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

    def test_12_cuenta_que_existe_recibe_el_enlace_al_portal(self):
        r = self.enviar(fila=self.FILA)
        (destino, enlace, minutos), = r.enviados
        self.assertEqual((destino, enlace, minutos),
                         ('alguien@tec.mx', 'https://lowtidesec.com/forgot-password/reset#t=TOKEN-DE-PRUEBA', 30))
        self.assertEqual(r.reservas, [{'tipo': 'reset'}])
        (_, _, accion, *_, detalle), = r.bitacora
        self.assertEqual((accion, detalle), ('auth.password_reset_requested', {'expires_minutes': 30}))

    def test_13_sin_llave_responde_igual_y_deja_un_evento(self):
        # Punto 4: sin CORREO_API_KEY el token no queda vivo y la bitácora dice por qué.
        r = self.enviar(fila=self.FILA, motivo='sin_llave')
        self.assertEqual(r.borrados, ['TOKEN-DE-PRUEBA'])
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
        pendiente = {'user_id': str(uuid.UUID(int=2)), 'org_id': str(uuid.UUID(int=1)), 'email': 'a@tec.mx'}
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

    def test_18_cuenta_desactivada_o_demo_apagada_no_cambia(self):
        pendiente = {'user_id': str(uuid.UUID(int=2)), 'org_id': str(uuid.UUID(int=1)), 'email': 'a@tec.mx'}
        for fila, razon in ((None, 'inactive'), ({'email': 'a@tec.mx', 'demo_off': True}, 'demo_off')):
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
        pendiente = {'user_id': str(uuid.UUID(int=2)), 'org_id': str(uuid.UUID(int=1)), 'email': 'a@tec.mx'}
        with self.falsos(token=pendiente, fila={'email': 'A@tec.mx', 'demo_off': False}) as r, \
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


if __name__ == '__main__':
    unittest.main(verbosity=2)

"""Enlace al correo (#28, RC-63) sin red: el correo, los tokens y límites en Valkey y las rutas con la base y Resend
falsos. Corren dentro del contenedor, porque cirdan.auth.routes importa fastapi, psycopg y redis, y usan el Valkey del
compose para los scripts de los tokens:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_enlace_sin_red.py

El Hecho cuando de punta a punta (HTTP, base y Resend simulado) está en pruebas/test_enlace.py.
"""
import contextlib
import io
import json
import logging
import os
import threading
import time
import unittest
import urllib.error
import uuid
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException

from cirdan import correo
from cirdan.auth import routes, sessions

ENLACE = 'http://portal.prueba/login/enlace#t=TOKEN-DE-PRUEBA-que-no-va-al-log'
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
    """cirdan/correo.py: solo el enlace y la duración, y el plan B de RC-327 sin correo ni token en el log."""

    def enviar(self, abrir):
        with mock.patch.object(correo, '_abrir', abrir), self.assertLogs('cirdan.correo', 'WARNING') as logs:
            motivo = correo.enviar_enlace(DESTINO, ENLACE, 15)
        texto = '\n'.join(logs.output)
        self.assertNotIn(DESTINO, texto)
        self.assertNotIn('TOKEN-DE-PRUEBA', texto)
        return motivo, texto

    def test_1_el_cuerpo_solo_lleva_el_enlace_y_cuanto_dura(self):
        asunto, texto, pagina = correo.cuerpo(ENLACE, 15)
        self.assertEqual(asunto, 'Tu enlace para entrar a LowTide')
        for parte in (texto, pagina):
            self.assertIn('15 minutos', parte)
            self.assertNotIn(DESTINO, parte)
        self.assertIn(ENLACE, texto)
        self.assertIn('href="http://portal.prueba/login/enlace#t=TOKEN-DE-PRUEBA-que-no-va-al-log"', pagina)
        # Un enlace con comillas no rompe el HTML.
        self.assertIn('&quot;', correo.cuerpo('http://x/"><script>', 15)[2])

    def test_2_aceptado_va_a_la_url_con_la_llave_y_sin_log(self):
        vistas = []

        def abrir(req):
            vistas.append(req)
            return 200

        with entorno(CORREO_API_KEY='llave-de-prueba', CORREO_API_URL='http://correo-falso:8025/emails',
                     CORREO_REMITENTE=None), mock.patch.object(correo, '_abrir', abrir):
            self.assertIsNone(correo.enviar_enlace(DESTINO, ENLACE, 15))
        req, = vistas
        self.assertEqual(req.full_url, 'http://correo-falso:8025/emails')
        self.assertEqual(req.get_header('Authorization'), 'Bearer llave-de-prueba')
        datos = json.loads(req.data)
        self.assertEqual((datos['from'], datos['to']), ('LowTide <acceso@lowtidesec.com>', [DESTINO]))

    def test_3_resend_que_no_acepta_deja_el_codigo_en_el_log(self):
        for codigo in (429, 401, 403, 500, 503):
            with self.subTest(codigo=codigo), entorno(CORREO_API_KEY='llave-de-prueba'):
                def abrir(req, codigo=codigo):
                    raise urllib.error.HTTPError(req.full_url, codigo, 'x', {}, io.BytesIO(b''))
                motivo, texto = self.enviar(abrir)
                self.assertEqual(motivo, str(codigo))
                self.assertIn('motivo=%d' % codigo, texto)

    def test_4_sin_respuesta_y_sin_llave(self):
        with entorno(CORREO_API_KEY='llave-de-prueba'):
            def abrir(req):
                raise TimeoutError('plazo')
            self.assertEqual(self.enviar(abrir)[0], 'sin_respuesta')
        with entorno(CORREO_API_KEY=None):
            llamadas = []
            motivo, texto = self.enviar(lambda req: llamadas.append(req))
            self.assertEqual((motivo, llamadas), ('sin_llave', []))
            self.assertIn('sin_llave', texto)


class TokensEnValkey(unittest.TestCase):
    """cirdan/auth/sessions.py contra el Valkey del compose: hash, 15 min, una vez, el nuevo anula y los topes."""

    def datos(self):
        return {'user_id': str(uuid.uuid4()), 'org_id': str(uuid.uuid4()), 'email': _al_azar() + '@ejemplo.com'}

    def test_5_token_de_32_bytes_guardado_solo_por_su_hash_y_15_minutos(self):
        datos = self.datos()
        token = sessions.create_link(datos)
        self.assertGreaterEqual(len(token), 43)
        valkey = sessions._valkey()
        self.assertIsNone(valkey.get('link:' + token))
        llave = 'link:' + sessions._digest(token)
        self.assertTrue(valkey.exists(llave))
        self.assertNotIn(token, valkey.get(llave))
        self.assertTrue(sessions.LINK_SECONDS - 5 <= valkey.ttl(llave) <= sessions.LINK_SECONDS)
        self.assertEqual(sessions.take_link(token), datos)
        self.assertIsNone(sessions.take_link(token))

    def test_6_dos_canjes_a_la_vez_solo_uno_entra(self):
        token = sessions.create_link(self.datos())
        resultados, salida = [], threading.Barrier(8)

        def canjear():
            salida.wait()
            resultados.append(sessions.take_link(token))

        hilos = [threading.Thread(target=canjear) for _ in range(8)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        self.assertEqual(sum(r is not None for r in resultados), 1)

    def test_7_pedir_otro_anula_el_anterior_y_borrar_el_que_no_salio(self):
        datos = self.datos()
        viejo, nuevo = sessions.create_link(datos), sessions.create_link(datos)
        self.assertIsNone(sessions.take_link(viejo))
        sessions.delete_link(nuevo)
        self.assertIsNone(sessions.take_link(nuevo))

    def test_8_tres_por_correo_y_diez_por_ip(self):
        ip = '203.0.113.%d' % (uuid.uuid4().int % 250)
        sessions._valkey().delete('link:req:ip:' + ip)
        email = _al_azar() + '@ejemplo.com'
        self.assertEqual([sessions.take_link_request(email, ip) for _ in range(4)], [True, True, True, False])
        otros = [sessions.take_link_request(_al_azar() + '@ejemplo.com', ip) for _ in range(8)]
        self.assertEqual(otros, [True] * 7 + [False])   # 3 + 7 = 10 por la IP
        sessions._valkey().delete('link:req:ip:' + ip)

    def test_9_tope_diario(self):
        dia = 'prueba-' + _al_azar()
        try:
            self.assertEqual([sessions.reserve_link_send(3, dia) for _ in range(5)], [1, 2, 3, 0, 0])
        finally:
            sessions._valkey().delete('link:day:' + dia)


class Rutas(unittest.TestCase):
    """cirdan/auth/routes.py sin base ni Resend: la respuesta, el envío después del 202 y el canje."""

    def request(self):
        return SimpleNamespace(client=SimpleNamespace(host='198.51.100.7'), headers={})

    def test_10_misma_respuesta_y_el_envio_va_despues(self):
        with mock.patch.object(routes.captcha, 'verify', return_value=True):
            respuestas = [routes.request_link(routes.LinkRequestIn(email=e, captcha='x'), self.request())
                          for e in ('Alguien@Ejemplo.com ', 'nadie@ejemplo.com', 'otra@gmail.com')]
        self.assertEqual({(r.status_code, r.body) for r in respuestas}, {(202, respuestas[0].body)})
        detalle = json.loads(respuestas[0].body)['detail']
        self.assertEqual(detalle, routes.LINK_SENT)
        self.assertIn('contraseña', detalle)
        self.assertIn('passkey', detalle)
        self.assertEqual(respuestas[0].headers['cache-control'], 'no-store')
        # Nada se buscó todavía: todo va en la tarea de después, con el correo normalizado.
        self.assertEqual(respuestas[0].background.args, ('alguien@ejemplo.com', '198.51.100.7'))

    def test_11_sin_captcha_400_antes_de_todo(self):
        with mock.patch.object(routes.captcha, 'verify', return_value=False), \
                mock.patch.object(routes, '_send_link') as enviar:
            with self.assertRaises(HTTPException) as e:
                routes.request_link(routes.LinkRequestIn(email='a@b.c'), self.request())
        self.assertEqual(e.exception.status_code, 400)
        enviar.assert_not_called()

    @contextlib.contextmanager
    def envio(self, encontrada=True, limite=True, tope=1, motivo=None):
        """_send_link con todo falso. Devuelve las llamadas a la bitácora, a Resend y a delete_link."""
        bitacora, enviados, borrados = [], [], []
        fila = {'organization_id': uuid.UUID(int=1), 'user_id': uuid.UUID(int=2)} if encontrada else None
        conn = mock.MagicMock()
        conn.execute.return_value.fetchone.return_value = fila

        @contextlib.contextmanager
        def transaccion(org=None):
            yield conn

        with mock.patch.object(routes, 'transaction', transaccion), \
                mock.patch.object(routes, 'audit', lambda *a: bitacora.append(a)), \
                mock.patch.object(routes.sessions, 'take_link_request', return_value=limite), \
                mock.patch.object(routes.sessions, 'reserve_link_send', return_value=tope), \
                mock.patch.object(routes.sessions, 'create_link', return_value='TOKEN-DE-PRUEBA'), \
                mock.patch.object(routes.sessions, 'delete_link', lambda t: borrados.append(t)), \
                mock.patch.object(routes.correo, 'enviar_enlace',
                                  lambda *a: enviados.append(a) or motivo), \
                entorno(PORTAL_URL='https://lowtidesec.com/', ENLACE_TOPE_DIARIO='80'):
            yield SimpleNamespace(bitacora=bitacora, enviados=enviados, borrados=borrados)

    def correr(self, email='alguien@tec.mx', **kw):
        with self.envio(**kw) as r, self.assertLogs('cirdan.auth.routes', 'WARNING') as logs:
            logging.getLogger('cirdan.auth.routes').warning('marca')  # assertLogs pide al menos una línea
            routes._send_link(email, '198.51.100.7')
        r.log = '\n'.join(logs.output)
        self.assertNotIn('TOKEN-DE-PRUEBA', r.log)
        self.assertNotIn(email, r.log)
        return r

    def test_12_envio_con_el_portal_de_la_variable_y_en_la_bitacora_sin_token(self):
        r = self.correr()
        (destino, enlace, minutos), = r.enviados
        self.assertEqual((destino, enlace, minutos),
                         ('alguien@tec.mx', 'https://lowtidesec.com/login/enlace#t=TOKEN-DE-PRUEBA', 15))
        (_, org, accion, *resto), = r.bitacora
        self.assertEqual(accion, 'auth.link_sent')
        self.assertNotIn('TOKEN-DE-PRUEBA', repr(r.bitacora))
        self.assertEqual(r.borrados, [])

    def test_13_cualquier_dominio_recibe_el_enlace(self):
        # Sin regla de dominio: llega con RC-269 (comentario de Ernesto del 10 nov).
        for email in ('alguien@gmail.com', 'otra@acme-demo.mx'):
            with self.subTest(email=email):
                self.assertEqual(len(self.correr(email).enviados), 1)

    def test_14_correo_que_no_existe_limite_y_tope_no_envian(self):
        for kw, aviso in (({'encontrada': False}, 'correo que no existe'), ({'limite': False}, 'límite de pedidos'),
                          ({'tope': 0}, 'enlace: tope diario alcanzado (80)')):
            with self.subTest(kw=kw):
                r = self.correr(**kw)
                self.assertEqual((r.enviados, r.bitacora), ([], []))
                self.assertIn(aviso, r.log)

    def test_15_si_resend_no_acepta_el_token_se_borra(self):
        r = self.correr(motivo='429')
        self.assertEqual(r.borrados, ['TOKEN-DE-PRUEBA'])
        (*_, detalles), = r.bitacora
        self.assertEqual(detalles, {'reason': '429'})
        self.assertEqual(r.bitacora[0][2], 'auth.link_send_failed')

    def test_16_canje_superadmin_sin_mfa_403_y_bitacora(self):
        bitacora = []
        conn = mock.MagicMock()
        fila_usuario = {'role': 'admin', 'email': 'equipo@lowtidesec.com', 'mfa_enabled': False}
        conn.execute.return_value.fetchone.side_effect = [fila_usuario, {'required': True}]

        @contextlib.contextmanager
        def transaccion(org=None):
            yield conn

        pendiente = {'user_id': str(uuid.uuid4()), 'org_id': str(uuid.uuid4()), 'email': 'equipo@lowtidesec.com'}
        with mock.patch.object(routes.sessions, 'take_link', return_value=pendiente), \
                mock.patch.object(routes, 'transaction', transaccion), \
                mock.patch.object(routes, 'audit', lambda *a: bitacora.append(a)), \
                mock.patch.object(routes, '_start_session') as sesion:
            with self.assertRaises(HTTPException) as e:
                routes.verify_link(routes.LinkVerifyIn(token='x' * 43), self.request(), mock.MagicMock())
        self.assertEqual((e.exception.status_code, e.exception.detail), (403, routes.OPERATOR_MFA_REQUIRED))
        sesion.assert_not_called()
        self.assertEqual((bitacora[0][2], bitacora[0][-1]), ('auth.link_rejected', {'reason': 'operator_mfa_required'}))

    def test_17_token_que_no_existe_401_sin_bitacora(self):
        with mock.patch.object(routes.sessions, 'take_link', return_value=None), \
                mock.patch.object(routes, 'audit') as auditar:
            with self.assertRaises(HTTPException) as e:
                routes.verify_link(routes.LinkVerifyIn(token='y' * 43), self.request(), mock.MagicMock())
        self.assertEqual((e.exception.status_code, e.exception.detail), (401, routes.LINK_INVALID))
        auditar.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)

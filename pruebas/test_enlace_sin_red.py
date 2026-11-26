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
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException

from cirdan import correo
from cirdan.auth import routes, sessions
from cirdan.auth.demo import HASH_DE_RELLENO
from pruebas import valkey_admin

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
        valkey = valkey_admin.cliente()
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
        valkey_admin.cliente().delete('link:req:ip:' + ip)
        email = _al_azar() + '@ejemplo.com'
        self.assertEqual([sessions.take_link_request(email, ip) for _ in range(4)], [True, True, True, False])
        otros = [sessions.take_link_request(_al_azar() + '@ejemplo.com', ip) for _ in range(8)]
        self.assertEqual(otros, [True] * 7 + [False])   # 3 + 7 = 10 por la IP
        valkey_admin.cliente().delete('link:req:ip:' + ip)

    def test_9_tope_diario(self):
        dia = 'prueba-' + _al_azar()
        try:
            self.assertEqual([sessions.reserve_link_send(3, uuid.uuid4(), dia) for _ in range(5)], [1, 2, 3, 0, 0])
        finally:
            for llave in valkey_admin.cliente().scan_iter('link:day:' + dia + '*'):
                valkey_admin.cliente().delete(llave)

    def test_9b_tope_diario_por_cuenta_sin_gastar_el_del_dia(self):
        # M2: pedir enlaces para un correo que existe y se conoce no deja a los demás sin enlace ese día.
        dia = 'prueba-' + _al_azar()
        cuenta, otra = uuid.uuid4(), uuid.uuid4()
        try:
            tope = sessions.MAX_LINKS_USER_DAY
            self.assertEqual([sessions.reserve_link_send(80, cuenta, dia) for _ in range(tope + 3)],
                             list(range(1, tope + 1)) + [-1, -1, -1])
            self.assertEqual(sessions.reserve_link_send(80, otra, dia), tope + 1)   # los -1 no gastaron el del día
            self.assertEqual(sessions.reserve_link_send(tope + 1, uuid.uuid4(), dia), 0)
            self.assertEqual(valkey_admin.cliente().get('link:day:' + dia), str(tope + 1))
        finally:
            for llave in valkey_admin.cliente().scan_iter('link:day:' + dia + '*'):
                valkey_admin.cliente().delete(llave)

    def test_7b_rastro_del_canje_rechazado(self):
        # M3: de un token que ya no sirve se sabe de qué cuenta era y por qué, sin el correo ni el token.
        datos = self.datos()
        usado = sessions.create_link(datos)
        self.assertEqual(sessions.take_link(usado), datos)
        esperado = {'user_id': datos['user_id'], 'org_id': datos['org_id']}
        self.assertEqual(sessions.link_trace(usado), dict(esperado, reason='used'))
        self.assertIsNone(sessions.link_trace(usado))   # una sola vez: reenviarlo no llena audit_log
        anulado = sessions.create_link(datos)
        vigente = sessions.create_link(datos)
        self.assertIsNone(sessions.take_link(anulado))
        self.assertEqual(sessions.link_trace(anulado), dict(esperado, reason='replaced'))
        valkey_admin.cliente().delete('link:' + sessions._digest(vigente))   # como si hubiera vencido
        self.assertIsNone(sessions.take_link(vigente))
        self.assertEqual(sessions.link_trace(vigente), dict(esperado, reason='expired'))
        rastro = valkey_admin.cliente().hgetall('link-rastro:' + sessions._digest(vigente))
        self.assertNotIn(datos['email'], repr(rastro))
        self.assertNotIn(vigente, repr(rastro))
        self.assertTrue(sessions.LINK_SECONDS < valkey_admin.cliente().ttl('link-rastro:' + sessions._digest(vigente))
                        <= sessions.LINK_TRACE_SECONDS)
        self.assertIsNone(sessions.link_trace(sessions.create_link(self.datos())[::-1]))   # un token que nunca existió
        self.assertIsNone(sessions.link_trace(None))

    def test_7c_el_que_no_salio_no_deja_rastro(self):
        token = sessions.create_link(self.datos())
        sessions.delete_link(token)
        self.assertIsNone(sessions.take_link(token))
        self.assertIsNone(sessions.link_trace(token))


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
    def envio(self, encontrada=True, limite=True, tope=1, motivo=None, huella='$argon2id$otra-huella'):
        """_send_link con todo falso. Devuelve las llamadas a la bitácora, a Resend, a delete_link y al tope."""
        bitacora, enviados, borrados, reservas = [], [], [], []
        fila = ({'organization_id': uuid.UUID(int=1), 'user_id': uuid.UUID(int=2), 'password_hash': huella}
                if encontrada else None)
        conn = mock.MagicMock()
        conn.execute.return_value.fetchone.return_value = fila

        @contextlib.contextmanager
        def transaccion(org=None):
            yield conn

        with mock.patch.object(routes, 'transaction', transaccion), \
                mock.patch.object(routes, 'audit', lambda *a: bitacora.append(a)), \
                mock.patch.object(routes.sessions, 'take_link_request', return_value=limite), \
                mock.patch.object(routes.sessions, 'reserve_link_send', lambda *a: reservas.append(a) or tope), \
                mock.patch.object(routes.sessions, 'create_link', return_value='TOKEN-DE-PRUEBA'), \
                mock.patch.object(routes.sessions, 'delete_link', lambda t: borrados.append(t)), \
                mock.patch.object(routes.correo, 'enviar_enlace',
                                  lambda *a: enviados.append(a) or motivo), \
                entorno(PORTAL_URL='https://lowtidesec.com/', ENLACE_TOPE_DIARIO='80'):
            yield SimpleNamespace(bitacora=bitacora, enviados=enviados, borrados=borrados, reservas=reservas)

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
        self.assertEqual(r.reservas, [(80, str(uuid.UUID(int=2)))])   # el tope del día y el de la cuenta

    def test_12b_el_portal_del_despliegue_sale_del_primer_origen(self):
        # M4: docker-compose.despliegue.yml deja PORTAL_URL vacía; el plan B de pruebas manda a su propio portal.
        for env, esperado in (({'PORTAL_URL': '', 'ALLOWED_ORIGINS': 'https://pruebas.lowtidesec.com'},
                               'https://pruebas.lowtidesec.com'),
                              ({'PORTAL_URL': '', 'ALLOWED_ORIGINS': 'https://lowtidesec.com,https://www.lowtidesec.com'},
                               'https://lowtidesec.com'),
                              ({'PORTAL_URL': 'http://portal.prueba/', 'ALLOWED_ORIGINS': 'https://lowtidesec.com'},
                               'http://portal.prueba'),
                              ({'PORTAL_URL': None, 'ALLOWED_ORIGINS': None}, 'http://localhost:3000')):
            with self.subTest(env=env), entorno(**env), mock.patch('cirdan.config._env_file', return_value={}):
                self.assertEqual(routes._portal_url(), esperado)

    def test_13_cualquier_dominio_recibe_el_enlace(self):
        # Sin regla de dominio: llega con RC-269 (comentario de Ernesto del 10 nov).
        for email in ('alguien@gmail.com', 'otra@acme-demo.mx'):
            with self.subTest(email=email):
                self.assertEqual(len(self.correr(email).enviados), 1)

    def test_14_correo_que_no_existe_limite_y_tope_no_envian(self):
        for kw, aviso in (({'encontrada': False}, 'correo que no existe'), ({'limite': False}, 'límite de pedidos'),
                          ({'tope': 0}, 'enlace: tope diario alcanzado (80)'),
                          ({'tope': -1}, 'enlace: tope diario de la cuenta alcanzado (5)')):
            with self.subTest(kw=kw):
                r = self.correr(**kw)
                self.assertEqual((r.enviados, r.bitacora), ([], []))
                self.assertIn(aviso, r.log)

    def test_14b_cuenta_de_demo_apagada_no_recibe_enlace(self):
        # A1: la cuenta de demo apagada sigue activa, con el hash de relleno y sin MFA. Ni correo ni cupo del día.
        r = self.correr('alex.morgan@acme-demo.mx', huella=HASH_DE_RELLENO)
        self.assertEqual((r.enviados, r.bitacora, r.reservas), ([], [], []))
        self.assertIn('cuenta sin contraseña (hash de relleno)', r.log)

    def test_15_si_resend_no_acepta_el_token_se_borra(self):
        r = self.correr(motivo='429')
        self.assertEqual(r.borrados, ['TOKEN-DE-PRUEBA'])
        (*_, detalles), = r.bitacora
        self.assertEqual(detalles, {'reason': '429'})
        self.assertEqual(r.bitacora[0][2], 'auth.link_send_failed')

    def test_16_canje_superadmin_sin_mfa_403_y_bitacora(self):
        bitacora = []
        conn = mock.MagicMock()
        fila_usuario = {'role': 'admin', 'email': 'equipo@lowtidesec.com', 'mfa_enabled': False, 'demo_off': False,
                        'password_hash': 'lt1$huella'}
        conn.execute.return_value.fetchone.side_effect = [fila_usuario, {'required': True}]

        @contextlib.contextmanager
        def transaccion(org=None):
            yield conn

        pendiente = {'user_id': str(uuid.uuid4()), 'org_id': str(uuid.uuid4()), 'email': 'equipo@lowtidesec.com',
                     'tag': routes.sessions.password_tag('lt1$huella')}
        with mock.patch.object(routes.sessions, 'take_link', return_value=pendiente), \
                mock.patch.object(routes, 'transaction', transaccion), \
                mock.patch.object(routes, 'audit', lambda *a: bitacora.append(a)), \
                mock.patch.object(routes, '_start_session') as sesion:
            with self.assertRaises(HTTPException) as e:
                routes.verify_link(routes.LinkVerifyIn(token='x' * 43), self.request(), mock.MagicMock())
        self.assertEqual((e.exception.status_code, e.exception.detail), (403, routes.OPERATOR_MFA_REQUIRED))
        sesion.assert_not_called()
        self.assertEqual((bitacora[0][2], bitacora[0][-1]), ('auth.link_rejected', {'reason': 'operator_mfa_required'}))

    def test_16c_canje_de_un_admin_sin_mfa_403_sin_token_de_alta(self):
        # RC-5: el Admin sin TOTP tampoco entra por enlace, y activarlo pide la contraseña: el 403 no trae token.
        for rol, esperado in (('admin', 403), ('analyst', 200), ('manager', 200)):
            with self.subTest(rol=rol):
                bitacora = []
                conn = mock.MagicMock()
                fila_usuario = {'role': rol, 'email': 'a@tec.mx', 'mfa_enabled': False, 'demo_off': False,
                                'password_hash': 'lt1$huella'}
                conn.execute.return_value.fetchone.side_effect = [fila_usuario, {'required': False}]

                @contextlib.contextmanager
                def transaccion(org=None):
                    yield conn

                pendiente = {'user_id': str(uuid.uuid4()), 'org_id': str(uuid.uuid4()), 'email': 'a@tec.mx',
                             'tag': routes.sessions.password_tag('lt1$huella')}
                with mock.patch.object(routes.sessions, 'take_link', return_value=pendiente), \
                        mock.patch.object(routes, 'transaction', transaccion), \
                        mock.patch.object(routes, 'audit', lambda *a: bitacora.append(a)), \
                        mock.patch.object(routes, '_clear_fails'), \
                        mock.patch.object(routes, '_start_session', return_value={'email': 'a@tec.mx'}) as sesion:
                    if esperado == 403:
                        with self.assertRaises(HTTPException) as e:
                            routes.verify_link(routes.LinkVerifyIn(token='x' * 43), self.request(), mock.MagicMock())
                        self.assertEqual((e.exception.status_code, e.exception.detail),
                                         (403, routes.ADMIN_MFA_PASSWORD))
                        sesion.assert_not_called()
                        self.assertEqual((bitacora[0][2], bitacora[0][-1]),
                                         ('auth.link_rejected', {'reason': 'admin_mfa_required'}))
                    else:
                        r = routes.verify_link(routes.LinkVerifyIn(token='x' * 43), self.request(), mock.MagicMock())
                        self.assertEqual(r['mfa_required'], False)
                        sesion.assert_called_once()

    def test_16b_canje_de_una_cuenta_de_demo_apagada_401_y_bitacora(self):
        # A1: si la cuenta se apagó después de pedir el enlace, tampoco entra.
        bitacora = []
        conn = mock.MagicMock()
        conn.execute.return_value.fetchone.return_value = {'role': 'admin', 'email': 'alex.morgan@acme-demo.mx',
                                                           'mfa_enabled': False, 'demo_off': True}

        @contextlib.contextmanager
        def transaccion(org=None):
            yield conn

        pendiente = {'user_id': str(uuid.uuid4()), 'org_id': str(uuid.uuid4()), 'email': 'alex.morgan@acme-demo.mx'}
        with mock.patch.object(routes.sessions, 'take_link', return_value=pendiente), \
                mock.patch.object(routes, 'transaction', transaccion), \
                mock.patch.object(routes, 'audit', lambda *a: bitacora.append(a)), \
                mock.patch.object(routes, '_start_session') as sesion:
            with self.assertRaises(HTTPException) as e:
                routes.verify_link(routes.LinkVerifyIn(token='x' * 43), self.request(), mock.MagicMock())
        self.assertEqual((e.exception.status_code, e.exception.detail), (401, routes.LINK_INVALID))
        sesion.assert_not_called()
        self.assertEqual((bitacora[0][2], bitacora[0][-1]), ('auth.link_rejected', {'reason': 'demo_off'}))
        sql, params = conn.execute.call_args_list[0].args
        self.assertIn('password_hash = %s', sql)
        self.assertEqual(params[0], HASH_DE_RELLENO)

    def test_17_token_que_no_existe_401_sin_bitacora(self):
        with mock.patch.object(routes.sessions, 'take_link', return_value=None), \
                mock.patch.object(routes.sessions, 'link_trace', return_value=None), \
                mock.patch.object(routes, 'audit') as auditar:
            with self.assertRaises(HTTPException) as e:
                routes.verify_link(routes.LinkVerifyIn(token='y' * 43), self.request(), mock.MagicMock())
        self.assertEqual((e.exception.status_code, e.exception.detail), (401, routes.LINK_INVALID))
        auditar.assert_not_called()

    def test_17b_token_usado_de_una_cuenta_401_y_bitacora(self):
        # M3: usado, anulado o vencido de una cuenta que existe queda en audit_log, sin el token.
        bitacora, orgs = [], []
        org, user = str(uuid.uuid4()), str(uuid.uuid4())

        @contextlib.contextmanager
        def transaccion(o=None):
            orgs.append(o)
            yield mock.MagicMock()

        for reason in ('used', 'replaced', 'expired'):
            with self.subTest(reason=reason), \
                    mock.patch.object(routes.sessions, 'take_link', return_value=None), \
                    mock.patch.object(routes.sessions, 'link_trace',
                                      return_value={'user_id': user, 'org_id': org, 'reason': reason}), \
                    mock.patch.object(routes, 'transaction', transaccion), \
                    mock.patch.object(routes, 'audit', lambda *a: bitacora.append(a)):
                with self.assertRaises(HTTPException) as e:
                    routes.verify_link(routes.LinkVerifyIn(token='z' * 43), self.request(), mock.MagicMock())
                self.assertEqual((e.exception.status_code, e.exception.detail), (401, routes.LINK_INVALID))
                (_, o, accion, actor, ip, _, _, detalles), = bitacora[-1:]
                self.assertEqual((o, accion, actor, ip, detalles),
                                 (org, 'auth.link_rejected', user, '198.51.100.7', {'reason': reason}))
                self.assertNotIn('z' * 43, repr(bitacora))
        self.assertEqual(orgs, [org] * 3)

    def test_17c_si_la_bitacora_falla_el_401_sale_igual(self):
        with mock.patch.object(routes.sessions, 'take_link', return_value=None), \
                mock.patch.object(routes.sessions, 'link_trace', side_effect=RuntimeError('valkey')), \
                self.assertLogs('cirdan.auth.routes', 'ERROR'):
            with self.assertRaises(HTTPException) as e:
                routes.verify_link(routes.LinkVerifyIn(token='z' * 43), self.request(), mock.MagicMock())
        self.assertEqual(e.exception.status_code, 401)


RAIZ = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('sh'), 'sin sh')
class RevisarLog(unittest.TestCase):
    """pruebas/enlace/revisar_log.sh con un docker falso que devuelve el log (M5 de la revisión)."""

    def correr(self, tokens, log):
        with tempfile.TemporaryDirectory() as tmp:
            docker = Path(tmp) / 'docker'
            (Path(tmp) / 'api.log').write_text(log, encoding='utf-8')
            docker.write_text('#!/bin/sh\ncat "%s"\n' % (Path(tmp) / 'api.log').as_posix(), encoding='utf-8')
            docker.chmod(0o755)
            salida = Path(tmp) / 'salida.log'
            salida.write_text(''.join('TOKEN_VISTO %s\n' % t for t in tokens), encoding='utf-8')
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ.get('PATH', ''))
            return subprocess.run(['sh', str(RAIZ / 'pruebas' / 'enlace' / 'revisar_log.sh'), str(salida)],
                                  capture_output=True, text=True, env=env, timeout=30, encoding='utf-8')

    def test_18_token_que_empieza_con_guion_tambien_se_encuentra(self):
        for token in ('-vAbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abc', '-fAbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abc',
                      'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde'):
            with self.subTest(token=token[:3]):
                r = self.correr(['otroTokenQueNoEstaEnElLog0123456789abcdefg', token], 'INFO algo %s algo\n' % token)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn('trae un token', r.stdout)

    def test_19_sin_tokens_en_el_log_pasa(self):
        r = self.correr(['-vAbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abc'], 'INFO nada que ver\n')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('1 revisados', r.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)

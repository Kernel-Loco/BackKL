"""Firma de la carta con Mifiel (RC-211), sin red ni base: cliente APIAuth, lectura del estado y rutas que cortan
antes de llegar a la base o a Mifiel."""
import asyncio
import base64
import hashlib
import http.client
import io
import json
import os
import unittest
import urllib.error
from datetime import date, datetime, timedelta, timezone
from email.parser import BytesParser
from email.policy import HTTP
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from cirdan.api import firmas, main
from cirdan.auth.deps import Session
from cirdan.firma import mifiel
from cirdan.recolectores import transporte

ORG = '20000000-0000-4000-8000-000000000002'
USER = '30000000-0000-4000-8000-000000000004'
APP_ID = 'CIRDAN_FAKE_app_id'
CLAVE_FALSA = 'CIRDAN_FAKE_clave_mifiel'
PDF = b'%PDF-1.4\nCIRDAN_FAKE_documento\n%%EOF\n'
BODY = {
    'fqdn': 'cirdan-fake-firma.example', 'signer_name': 'Nombre de prueba', 'signer_title': 'Representante',
    'signer_email': 'test@example.com', 'valid_from': '2026-01-01', 'valid_until': '2099-01-01',
    'passive_monitoring_confirmed': True, 'letter_base64': base64.b64encode(PDF).decode(),
    'template_version': 1, 'activities': [1, 2],
}
ADMIN = Session('CIRDAN_FAKE_session', USER, ORG, 'admin', 'test@example.com')
AJENA = Session('CIRDAN_FAKE_session', USER, ORG, 'admin', 'test@example.com',
                home_org_id='20000000-0000-4000-8000-000000000004', platform_admin=True)


def http_error(url, codigo):
    return urllib.error.HTTPError(url, codigo, 'error', {}, io.BytesIO(b'{"errors":[{"details":"test@example.com"}]}'))


class Red:
    """Sustituto de transporte.descargar: guarda cada petición y responde lo que se le pida."""

    def __init__(self, *respuestas):
        self.respuestas, self.peticiones = list(respuestas), []

    def __call__(self, req, plazo, tope, cronometro, tipo=None):
        self.peticiones.append((req, plazo, tope, tipo))
        respuesta = self.respuestas.pop(0)
        if isinstance(respuesta, BaseException):
            raise respuesta
        return respuesta


def cliente(*respuestas, environment='sandbox'):
    red = Red(*respuestas)
    return mifiel.Cliente(environment, APP_ID, CLAVE_FALSA, descargar=red, cronometro=lambda: 100.0), red


class ApiAuth(unittest.TestCase):
    def test_1_vectores_publicos_del_sdk(self):
        # test/api_auth/test_signature.py del SDK de Python de Mifiel: llave 'secret_key', GET, Content-Type text/json
        # y la fecha de date.fromordinal(735999). La ruta de las dos URL es '' (sin path).
        fecha = date.fromordinal(735999).strftime('%a, %d %b %Y %H:%M:%S GMT')
        for url, cuerpo, firma in (('http://some-url.com', b'some-body', 'T9lDIpknHXt1jDcoiU0YnHi4flA='),
                                   ('http://www.some-url.com', b'', 'Z+e8CG9ZGQ0YFxrKEYltxVu4tRU=')):
            with self.subTest(url=url):
                h = mifiel.encabezados('app', 'secret_key', 'GET', url, cuerpo, 'text/json', fecha)
                self.assertEqual(h['Authorization'], 'APIAuth app:%s' % firma)
                self.assertEqual(h['Content-MD5'], base64.b64encode(hashlib.md5(cuerpo).digest()).decode())

    def test_2_ruta_y_query_entran_en_la_firma(self):
        fecha = 'Fri, 05 Feb 2016 00:00:00 GMT'
        a = mifiel.encabezados(APP_ID, CLAVE_FALSA, 'GET', 'https://x.example/api/v1/documents/1', b'', '', fecha)
        b = mifiel.encabezados(APP_ID, CLAVE_FALSA, 'GET', 'https://x.example/api/v1/documents/2', b'', '', fecha)
        c = mifiel.encabezados(APP_ID, CLAVE_FALSA, 'GET', 'https://x.example/api/v1/documents/1?a=1', b'', '', fecha)
        self.assertEqual(len({a['Authorization'], b['Authorization'], c['Authorization']}), 3)
        self.assertNotIn('Content-Type', a)
        self.assertNotIn(CLAVE_FALSA, json.dumps(a))


class Cliente(unittest.TestCase):
    def test_3_apagado_no_abre_conexion(self):
        for valor in ('apagado', '', 'otro', 'production'):
            with self.subTest(valor=valor), \
                    patch.dict(os.environ, {'FIRMA_MODO': valor, 'MIFIEL_APP_ID': APP_ID,
                                            'MIFIEL_APP_SECRET': CLAVE_FALSA}), \
                    patch.object(transporte, 'descargar') as red:
                self.assertIsNone(mifiel.entorno())
                with self.assertRaises(mifiel.Apagado):
                    mifiel.cliente()
                red.assert_not_called()

    def test_4_sin_llaves_o_de_otro_entorno(self):
        with patch.dict(os.environ, {'FIRMA_MODO': 'sandbox', 'MIFIEL_APP_ID': '', 'MIFIEL_APP_SECRET': ''}):
            with self.assertRaises(mifiel.Apagado):
                mifiel.cliente()
        with patch.dict(os.environ, {'FIRMA_MODO': 'sandbox', 'MIFIEL_APP_ID': APP_ID, 'MIFIEL_APP_SECRET': CLAVE_FALSA}):
            self.assertEqual(mifiel.cliente().base, 'https://app-sandbox.mifiel.com/api/v1/')
            with self.assertRaises(mifiel.Apagado):
                mifiel.cliente('production')
        with patch.dict(os.environ, {'FIRMA_MODO': 'produccion', 'MIFIEL_APP_ID': APP_ID,
                                     'MIFIEL_APP_SECRET': CLAVE_FALSA}):
            self.assertEqual(mifiel.cliente().base, 'https://app.mifiel.com/api/v1/')

    def test_5_crear_manda_multipart_firmado(self):
        c, red = cliente(json.dumps({'id': 'doc-1', 'original_hash': hashlib.sha256(PDF).hexdigest()}).encode())
        creado = c.crear(PDF, 'Nombre\r\nX-Otro: 1', 'test@example.com', 'solicitud-1')
        self.assertEqual(creado, {'id': 'doc-1', 'original_hash': hashlib.sha256(PDF).hexdigest()})
        req, plazo, tope, tipo = red.peticiones[0]
        self.assertEqual((req.get_method(), req.full_url), ('POST', 'https://app-sandbox.mifiel.com/api/v1/documents'))
        self.assertEqual((plazo, tope), (100.0 + mifiel.PLAZO_DESCARGA, mifiel.TOPE_JSON))
        self.assertTrue(req.get_header('Authorization').startswith('APIAuth %s:' % APP_ID))
        self.assertEqual(req.get_header('Content-md5'), base64.b64encode(hashlib.md5(req.data).digest()).decode())
        fecha = req.get_header('Date')
        esperado = mifiel.firma_apiauth(CLAVE_FALSA, 'POST', req.get_header('Content-type'),
                                        req.get_header('Content-md5'), '/api/v1/documents', fecha)
        self.assertEqual(req.get_header('Authorization'), 'APIAuth %s:%s' % (APP_ID, esperado))
        mensaje = BytesParser(policy=HTTP).parsebytes(
            b'Content-Type: ' + req.get_header('Content-type').encode() + b'\r\n\r\n' + req.data)
        partes = {p.get_param('name', header='content-disposition'): p for p in mensaje.iter_parts()}
        self.assertEqual(partes['file'].get_payload(decode=True), PDF)
        self.assertEqual(partes['signatories[0][name]'].get_content().strip(), 'Nombre X-Otro: 1')
        self.assertEqual(partes['signatories[0][email]'].get_content().strip(), 'test@example.com')
        self.assertEqual(partes['send_invites'].get_content().strip(), 'true')
        self.assertEqual(partes['days_to_expire'].get_content().strip(), '7')
        self.assertEqual(partes['external_id'].get_content().strip(), 'solicitud-1')
        self.assertNotIn('tax_id', req.data.decode('latin-1'))
        self.assertNotIn(CLAVE_FALSA.encode(), req.data)

    def test_6_errores_con_texto_propio(self):
        url = 'https://app-sandbox.mifiel.com/api/v1/documents/doc-1'
        casos = ((http_error(url, 404), mifiel.NoEncontrado), (http_error(url, 423), mifiel.NoListo),
                 (http_error(url, 401), mifiel.FirmaError), (http_error(url, 500), mifiel.FirmaError),
                 (transporte.PlazoVencido('x'), mifiel.FirmaError), (transporte.Redirigida(302, 'x'), mifiel.FirmaError),
                 (ValueError('respuesta de más de 1 bytes'), mifiel.FirmaError), (OSError('x'), mifiel.FirmaError),
                 (b'no es json', mifiel.FirmaError), (b'[1]', mifiel.FirmaError))
        for respuesta, clase in casos:
            c, _ = cliente(respuesta)
            with self.subTest(respuesta=repr(respuesta)), self.assertRaises(clase) as error:
                c.consultar('doc-1')
            texto = str(error.exception) + repr(error.exception) + repr(c)
            self.assertNotIn(CLAVE_FALSA, texto)
            self.assertNotIn('test@example.com', texto)
            self.assertIsNone(error.exception.__cause__)

    def test_7_crear_sin_id_falla(self):
        for respuesta in (b'{}', b'{"id": ""}', b'{"id": 5}'):
            c, _ = cliente(respuesta)
            with self.subTest(respuesta=respuesta), self.assertRaises(mifiel.FirmaError):
                c.crear(PDF, 'Nombre', 'test@example.com', 'solicitud-1')

    def test_8_descargas_y_borrado(self):
        c, red = cliente(b'%PDF-firmado', b'<xml/>', b'', http_error('u', 404))
        self.assertEqual(c.pdf_firmado('doc/1'), b'%PDF-firmado')
        self.assertEqual(c.xml('doc/1'), b'<xml/>')
        c.borrar('doc/1')
        c.borrar('doc/1')    # un 404 al borrar cuenta como borrado
        urls = [(r.get_method(), r.full_url) for r, *_ in red.peticiones]
        base = 'https://app-sandbox.mifiel.com/api/v1/documents/doc%2F1'
        self.assertEqual(urls, [('GET', base + '/file_signed'), ('GET', base + '/xml'), ('DELETE', base),
                                ('DELETE', base)])
        self.assertEqual(red.peticiones[0][2:], (mifiel.TOPE_ARCHIVO, 'application/pdf'))


class Interpretar(unittest.TestCase):
    SHA = hashlib.sha256(PDF).digest()
    AHORA = datetime(2026, 11, 22, 12, tzinfo=timezone.utc)

    def estado(self, **doc):
        return mifiel.interpretar(doc, self.SHA, self.AHORA)

    def test_9_firmada_con_el_mismo_original(self):
        estado, firmado, error = self.estado(signed_by_all=True, original_hash=self.SHA.hex().upper(),
                                             signed_at='2026-11-21T10:00:00Z')
        self.assertEqual((estado, error), ('signed', None))
        self.assertEqual(firmado, datetime(2026, 11, 21, 10, tzinfo=timezone.utc))

    def test_10_firmada_con_otro_original_sigue_enviada(self):
        self.assertEqual(self.estado(signed_by_all=True, original_hash='00' * 32),
                         ('sent', None, 'Mifiel firmó un archivo distinto al que se mandó.'))
        self.assertEqual(self.estado(signed_by_all=True)[0], 'sent')

    def test_11_rechazada_vencida_y_pendiente(self):
        self.assertEqual(self.estado(state='Rejected')[0], 'rejected')
        self.assertEqual(self.estado(signers=[{'state': 'declined'}])[0], 'rejected')
        pasado = (self.AHORA - timedelta(minutes=1)).isoformat()
        futuro = (self.AHORA + timedelta(days=1)).isoformat()
        self.assertEqual(self.estado(expires_at=pasado)[0], 'expired')
        self.assertEqual(self.estado(expires_at=futuro, signed=False)[0], 'sent')
        self.assertEqual(self.estado(expires_at='no-fecha')[0], 'sent')
        self.assertEqual(self.estado(signed_by_all=False, state='pending')[0], 'sent')


class Rutas(unittest.TestCase):
    def test_12_xml_bien_formado_sin_doctype(self):
        self.assertTrue(firmas._xml_bien_formado(b'<?xml version="1.0"?><electronicDocument><a>1</a></electronicDocument>'))
        bomba = (b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><l>&b;</l>')
        externa = b'<?xml version="1.0"?><!DOCTYPE l SYSTEM "http://example.com/x.dtd"><l/>'
        for datos in (bomba, externa, b'<a>', b'', b'%PDF-1.4', b'<a></b>'):
            with self.subTest(datos=datos[:30]):
                self.assertFalse(firmas._xml_bien_formado(datos))

    def test_13_apagado_da_503_sin_base_ni_red(self):
        with patch.dict(os.environ, {'FIRMA_MODO': 'apagado'}), \
                patch.object(firmas, 'transaction', side_effect=AssertionError('no debe tocar la base')), \
                patch.object(transporte, 'descargar', side_effect=AssertionError('no debe llamar a Mifiel')), \
                patch.object(firmas.cartas, 'guardar', side_effect=AssertionError('no debe guardar')):
            with self.assertRaises(HTTPException) as error:
                firmas._enviar(dict(BODY), None, ADMIN)
        self.assertEqual(error.exception.status_code, 503)

    def test_14_datos_invalidos_antes_de_mifiel(self):
        malos = ({**BODY, 'letter_base64': base64.b64encode(b'no es pdf').decode()},
                 {**BODY, 'valid_until': '2025-01-01'}, {**BODY, 'extra': 1},
                 {**BODY, 'letter_base64': base64.b64encode(b'%PDF-' + b'0' * (5 * 1024 * 1024) + b'%%EOF').decode()})
        with patch.dict(os.environ, {'FIRMA_MODO': 'sandbox', 'MIFIEL_APP_ID': APP_ID, 'MIFIEL_APP_SECRET': CLAVE_FALSA}), \
                patch.object(firmas, 'transaction', side_effect=AssertionError('no debe tocar la base')), \
                patch.object(transporte, 'descargar', side_effect=AssertionError('no debe llamar a Mifiel')):
            for body in malos:
                with self.subTest(campos=sorted(body)), self.assertRaises(HTTPException) as error:
                    firmas._enviar(body, None, ADMIN)
                self.assertIn(error.exception.status_code, (413, 422))

    def test_15_superadmin_en_empresa_ajena_da_403(self):
        with patch.object(firmas, 'transaction', side_effect=AssertionError('no debe tocar la base')):
            for llamada in (lambda: firmas._enviar(dict(BODY), None, AJENA),
                            lambda: firmas._subir({**BODY, 'xml_base64': ''}, None, AJENA),
                            lambda: firmas._aceptar('00000000-0000-4000-8000-000000000000', {'confirm_fqdn': 'x'},
                                                    None, AJENA),
                            lambda: firmas.refresh_signature_request('x', None, AJENA),
                            lambda: firmas.cancel_signature_request('x', None, AJENA),
                            # La lista también: trae nombre, cargo y correo de quien firma (sesion_datos-2).
                            lambda: firmas.list_signature_requests(AJENA)):
                with self.assertRaises(HTTPException) as error:
                    llamada()
                self.assertEqual(error.exception.status_code, 403)

    def test_16_id_mal_formado_da_404(self):
        for valor in ('x', '', '1; DROP TABLE x', None):
            with self.subTest(valor=valor), self.assertRaises(HTTPException) as error:
                firmas._id(valor)
            self.assertEqual(error.exception.status_code, 404)

    def test_17_subida_valida_el_xml(self):
        with patch.object(firmas, 'transaction', side_effect=AssertionError('no debe tocar la base')):
            casos = ((BODY, 422), ({**BODY, 'xml_base64': '!!'}, 422),
                     ({**BODY, 'xml_base64': base64.b64encode(b'<!DOCTYPE a><a/>').decode()}, 422),
                     ({**BODY, 'xml_base64': base64.b64encode(b'<a>' + b'0' * firmas.MAX_XML + b'</a>').decode()}, 413))
            for body, codigo in casos:
                with self.subTest(codigo=codigo), self.assertRaises(HTTPException) as error:
                    firmas._subir(body, None, ADMIN)
                self.assertEqual(error.exception.status_code, codigo)

    def test_18_sin_habilitar_no_lee_el_cuerpo(self):
        async def receive():
            raise AssertionError('no debe leer el cuerpo')
        scope = {'type': 'http', 'method': 'POST', 'path': '/', 'headers': []}
        with patch.dict(os.environ, {'CARTA_ALTA_ENABLED': 'false'}):
            for ruta in (firmas.create_signature_request(Request(scope, receive), ADMIN),
                         firmas.upload_signed_letter(Request(scope, receive), ADMIN),
                         firmas.accept_signature_request('x', Request(scope, receive), ADMIN)):
                with self.assertRaises(HTTPException) as error:
                    asyncio.run(ruta)
                self.assertEqual(error.exception.status_code, 409)

    def test_19_topes_de_las_rutas_con_archivos(self):
        self.assertEqual(main.TOPES_POR_RUTA[('POST', '/api/v1/signature-requests')][0], firmas.MAX_ALTA_BODY)
        self.assertEqual(main.TOPES_POR_RUTA[('POST', '/api/v1/signature-uploads')][0], firmas.MAX_SUBIDA_BODY)
        self.assertGreater(firmas.MAX_SUBIDA_BODY, (firmas.MAX_CARTA + firmas.MAX_XML) * 4 // 3)
        rutas = {(m, r.path) for r in firmas.router.routes for m in r.methods}
        for ruta in ('/api/v1/signature-requests', '/api/v1/signature-uploads',
                     '/api/v1/signature-requests/{request_id}/refresh', '/api/v1/signature-requests/{request_id}/cancel',
                     '/api/v1/signature-requests/{request_id}/accept'):
            self.assertIn(('POST', ruta), rutas)
        self.assertIn(('GET', '/api/v1/signature-requests'), rutas)


class Revision(unittest.TestCase):
    """Arreglos de la revisión de riesgo de RC-211 que se prueban sin base."""

    def test_20_errores_de_http_client_salen_como_incierto(self):
        # tiempos_externa-1: IncompleteRead, BadStatusLine o LineTooLong no son OSError y antes salían como un 500.
        for falla in (http.client.IncompleteRead(b'{"id": "doc'), http.client.BadStatusLine('x'),
                      http.client.LineTooLong('header line'), http.client.RemoteDisconnected('x')):
            c, _ = cliente(falla)
            with self.subTest(falla=type(falla).__name__), self.assertRaises(mifiel.Incierto) as error:
                c.crear(PDF, 'Nombre', 'test@example.com', 'solicitud-1')
            self.assertIsNone(error.exception.__cause__)
            self.assertNotIn('test@example.com', str(error.exception))

    def test_21_incierto_solo_si_pudo_llegar(self):
        # sesion_datos-3: lo que pudo crear el documento es Incierto; un 4xx o un 401 dicen que Mifiel no lo creó.
        url = 'https://app-sandbox.mifiel.com/api/v1/documents'
        inciertos = (http_error(url, 500), http_error(url, 503), transporte.PlazoVencido('x'), OSError('x'),
                     ValueError('respuesta de más de 1 bytes'), b'no es json', b'{}', b'{"id": 5}')
        for respuesta in inciertos:
            c, _ = cliente(respuesta)
            with self.subTest(respuesta=repr(respuesta)[:40]), self.assertRaises(mifiel.Incierto):
                c.crear(PDF, 'Nombre', 'test@example.com', 'solicitud-1')
        for respuesta in (http_error(url, 422), http_error(url, 401), http_error(url, 404),
                          transporte.Redirigida(302, 'x')):
            c, _ = cliente(respuesta)
            with self.subTest(respuesta=repr(respuesta)[:40]), self.assertRaises(mifiel.FirmaError) as error:
                c.crear(PDF, 'Nombre', 'test@example.com', 'solicitud-1')
            self.assertNotIsInstance(error.exception, mifiel.Incierto)

    def test_22_crear_usa_el_plazo_de_las_descargas(self):
        c, red = cliente(json.dumps({'id': 'doc-1', 'original_hash': None}).encode())
        c.crear(PDF, 'Nombre', 'test@example.com', 'solicitud-1')
        self.assertEqual(red.peticiones[0][1], 100.0 + mifiel.PLAZO_DESCARGA)
        c, red = cliente(b'{"id": "doc-1"}')
        c.consultar('doc-1')
        self.assertEqual(red.peticiones[0][1], 100.0 + mifiel.PLAZO)

    def test_23_las_columnas_esconden_al_firmante_fuera_de_una_abierta(self):
        # base-2: la regla vive en COLUMNAS, que usan la lista, refresh, cancel y accept.
        for campo in ('signer_name', 'signer_title', 'signer_email::text'):
            self.assertIn('CASE WHEN %s THEN %s END' % (firmas._VISIBLE, campo), firmas.COLUMNAS)
        self.assertNotIn(', signer_name,', firmas.COLUMNAS)


if __name__ == '__main__':
    unittest.main()

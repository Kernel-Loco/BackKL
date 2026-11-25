"""Firma de la carta con Mifiel (RC-211) contra PostgreSQL y por HTTP, con un Mifiel falso. Solo en una base de
pruebas aislada (CIRDAN_TEST_DB_ISOLATED=true), como test_alta_dominio_integracion.py. Nunca llama a Mifiel."""
import asyncio
import base64
import hashlib
import http.client
import io
import json
import os
import tempfile
import unittest
import urllib.error
import uuid
from email.parser import BytesParser
from email.policy import HTTP
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

import psycopg
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI

from cirdan.api import firmas, v1
from cirdan.auth.deps import Session
from cirdan.db import transaction
from cirdan.recolectores import transporte

ORG = '20000000-0000-4000-8000-000000000004'      # LowTide (semilla 015), con lugar para dominios nuevos
USER = '30000000-0000-4000-8000-000000000006'
OTHER_ORG = '20000000-0000-4000-8000-000000000001'
OTHER_USER = '30000000-0000-4000-8000-000000000001'
KEY = b'd' * 32
PDF = b'%PDF-1.4\nCIRDAN_FAKE_carta_por_firmar\n%%EOF\n'
PDF_FIRMADO = b'%PDF-1.4\nCIRDAN_FAKE_carta_firmada\n%%EOF\n'
XML = b'<?xml version="1.0" encoding="UTF-8"?><electronicDocument><nom151>CIRDAN_FAKE</nom151></electronicDocument>'
SANDBOX = 'https://app-sandbox.mifiel.com/api/v1/'
PRODUCCION = 'https://app.mifiel.com/api/v1/'


def http_error(codigo):
    return urllib.error.HTTPError(SANDBOX, codigo, 'error', {}, io.BytesIO(b'{}'))


class MifielFalso:
    """Sustituto de transporte.descargar que hace de la API de Mifiel (sandbox o producción, nunca la real).

    crear_falla es la excepción que lanza POST documents. Con crear_despues, el documento queda creado aunque la
    respuesta no llegue (plazo vencido o conexión cortada)."""

    def __init__(self):
        self.docs, self.llamadas = {}, []
        self.crear_falla, self.crear_despues, self.hash_distinto = None, False, False

    def __call__(self, req, plazo, tope, cronometro, tipo=None):
        assert req.full_url.startswith((SANDBOX, PRODUCCION)), req.full_url
        assert req.get_header('Authorization', '').startswith('APIAuth CIRDAN_FAKE_app_id:')
        metodo, ruta = req.get_method(), urlsplit(req.full_url).path.removeprefix('/api/v1/')
        self.llamadas.append((metodo, ruta))
        if (metodo, ruta) == ('POST', 'documents'):
            if self.crear_falla and not self.crear_despues:
                raise self.crear_falla
            mensaje = BytesParser(policy=HTTP).parsebytes(
                b'Content-Type: ' + req.get_header('Content-type').encode() + b'\r\n\r\n' + req.data)
            partes = {p.get_param('name', header='content-disposition'): p for p in mensaje.iter_parts()}
            pdf = partes['file'].get_payload(decode=True)
            doc_id = 'CIRDAN_FAKE_doc_%s' % uuid.uuid4().hex[:8]
            self.docs[doc_id] = {'pdf': pdf, 'estado': {}, 'borrado': False,
                                 'external_id': partes['external_id'].get_content().strip()}
            if self.crear_falla:
                raise self.crear_falla
            original = '00' * 32 if self.hash_distinto else hashlib.sha256(pdf).hexdigest()
            return json.dumps({'id': doc_id, 'original_hash': original}).encode()
        partes = ruta.split('/')
        doc = self.docs.get(unquote(partes[1]))
        if doc is None or doc['borrado']:
            raise http_error(404)
        if metodo == 'DELETE':
            doc['borrado'] = True
            return b''
        if len(partes) == 2:
            return json.dumps({'id': partes[1], 'original_hash': hashlib.sha256(doc['pdf']).hexdigest(),
                               'signers': [{'email': 'test@example.com', 'state': 'pending'}], **doc['estado']}).encode()
        return {'file_signed': PDF_FIRMADO, 'xml': XML}[partes[2]]

    def firmar(self, doc_id):
        self.docs[doc_id]['estado'] = {'signed_by_all': True, 'signed_at': '2026-11-21T16:00:00Z'}


def pedir(app, metodo, path, body=None):
    async def call():
        payload = json.dumps(body).encode() if body is not None else b''
        messages, sent = [], False

        async def receive():
            nonlocal sent
            if sent:
                return {'type': 'http.disconnect'}
            sent = True
            return {'type': 'http.request', 'body': payload, 'more_body': False}

        async def send(message):
            messages.append(message)

        scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': metodo,
                 'scheme': 'http', 'path': path, 'raw_path': path.encode(), 'query_string': b'',
                 'headers': [(b'content-type', b'application/json')], 'client': ('127.0.0.1', 1234),
                 'server': ('test', 80)}
        await app(scope, receive, send)
        status = next(m['status'] for m in messages if m['type'] == 'http.response.start')
        text = b''.join(m.get('body', b'') for m in messages if m['type'] == 'http.response.body').decode()
        return SimpleNamespace(status_code=status, text=text, json=lambda: json.loads(text))
    return asyncio.run(call())


@unittest.skipUnless(os.environ.get('CIRDAN_TEST_DB_ISOLATED') == 'true', 'Requiere una base de pruebas aislada')
class FirmaBase(unittest.TestCase):
    def setUp(self):
        self.admin = Session('CIRDAN_FAKE_session', USER, ORG, 'admin', 'test@example.com')
        self.otro = Session('CIRDAN_FAKE_session', OTHER_USER, OTHER_ORG, 'admin', 'otro@example.com')
        self.app = FastAPI()
        self.app.include_router(v1.router)
        self.app.include_router(firmas.router)
        self.mifiel = MifielFalso()
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        for p in (patch.dict(os.environ, {'CARTA_ALTA_ENABLED': 'true', 'COOKIE_SECURE': 'false',
                                          'CARTA_STORAGE_DIR': self.dir.name, 'FIRMA_MODO': 'sandbox',
                                          'MIFIEL_APP_ID': 'CIRDAN_FAKE_app_id',
                                          'MIFIEL_APP_SECRET': 'CIRDAN_FAKE_clave_mifiel'}),
                  patch('cirdan.cartas._key', return_value=KEY),
                  patch.object(v1, 'client_ip', return_value='127.0.0.1'),
                  patch.object(firmas, 'client_ip', return_value='127.0.0.1'),
                  patch.object(firmas, 'ESPERA_CONSULTA', 0),
                  patch.object(transporte, 'descargar', self.mifiel)):
            p.start()
            self.addCleanup(p.stop)
        self.sesion = patch('cirdan.auth.deps.current_session', return_value=self.admin)
        self.como = self.sesion.start()
        self.addCleanup(self.sesion.stop)

    def body(self, fqdn=None, **cambios):
        fqdn = fqdn or 'cirdan-fake-firma-%s.example' % uuid.uuid4().hex[:10]
        return {'fqdn': fqdn, 'signer_name': 'Nombre de prueba', 'signer_title': 'Representante',
                'signer_email': 'test@example.com', 'valid_from': '2020-01-01', 'valid_until': '2099-01-01',
                'passive_monitoring_confirmed': True, 'letter_base64': base64.b64encode(PDF).decode(),
                'template_version': 1, 'activities': [2, 1], **cambios}

    def descifrar(self, key, *aad):
        blob = (Path(self.dir.name) / key).read_bytes()
        return AESGCM(KEY).decrypt(blob[3:15], blob[15:], ('%s:%s:%s' % (*aad, key)).encode())

    def fila(self, request_id, org=ORG):
        with transaction(org) as conn:
            return conn.execute('SELECT * FROM signature_requests WHERE id = %s', (request_id,)).fetchone()

    def enviar(self, body=None):
        r = pedir(self.app, 'POST', '/api/v1/signature-requests', body or self.body())
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def produccion(self):
        """Modo producción por el resto de la prueba: solo una carta de producción se puede confirmar (base-1)."""
        p = patch.dict(os.environ, {'FIRMA_MODO': 'produccion'})
        p.start()
        self.addCleanup(p.stop)

    def cancelar(self, request_id):
        r = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/cancel' % request_id)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_1_enviar_consultar_y_confirmar_un_dominio_nuevo(self):
        self.produccion()
        body = self.body()
        enviada = self.enviar(body)
        self.assertEqual((enviada['status'], enviada['environment'], enviada['fqdn']),
                         ('sent', 'production', body['fqdn']))
        # Abierta, la lista trae al firmante (base-2: solo mientras está abierta y la carta no venció).
        self.assertEqual((enviada['signer_name'], enviada['signer_email']), ('Nombre de prueba', 'test@example.com'))
        fila = self.fila(enviada['id'])
        doc_id = fila['provider_document_id']
        self.assertEqual(self.mifiel.docs[doc_id]['external_id'], enviada['id'])
        self.assertEqual(bytes(fila['unsigned_sha256']), hashlib.sha256(PDF).digest())
        self.assertEqual(self.descifrar(fila['unsigned_document_key'], ORG, enviada['id']), PDF)
        self.assertNotIn(PDF, (Path(self.dir.name) / fila['unsigned_document_key']).read_bytes())
        # Una sola abierta por dominio.
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests', body).status_code, 409)

        pendiente = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % enviada['id'])
        self.assertEqual((pendiente.status_code, pendiente.json()['status']), (200, 'sent'))
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests/%s/accept' % enviada['id'],
                               {'confirm_fqdn': body['fqdn']}).status_code, 409)
        self.mifiel.firmar(doc_id)
        firmada = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % enviada['id']).json()
        self.assertEqual(firmada['status'], 'signed')
        fila = self.fila(enviada['id'])
        self.assertEqual(self.descifrar(fila['signed_document_key'], ORG, enviada['id']), PDF_FIRMADO)
        self.assertEqual(self.descifrar(fila['evidence_key'], ORG, enviada['id']), XML)
        self.assertEqual(bytes(fila['evidence_sha256']), hashlib.sha256(XML).digest())
        # Firmada, ya no se consulta a Mifiel.
        antes = len(self.mifiel.llamadas)
        pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % enviada['id'])
        self.assertEqual(len(self.mifiel.llamadas), antes)

        mal = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/accept' % enviada['id'],
                    {'confirm_fqdn': 'otro.example'})
        self.assertEqual(mal.status_code, 422)
        ok = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/accept' % enviada['id'],
                   {'confirm_fqdn': body['fqdn'].upper() + '.'})
        self.assertEqual(ok.status_code, 200, ok.text)
        datos = ok.json()
        self.assertEqual((datos['domain']['fqdn'], datos['domain']['status'], datos['signature_request']['status']),
                         (body['fqdn'], 'pending_verification', 'accepted'))
        self.assertEqual(datos['domain']['authorization']['status'], 'valid')
        with transaction(ORG) as conn:
            carta = conn.execute('SELECT * FROM domain_authorizations WHERE signature_request_id = %s',
                                 (enviada['id'],)).fetchone()
            acciones = conn.execute('SELECT action, details::text AS details FROM audit_log WHERE entity_id = %s '
                                    'OR (entity_id = %s) ORDER BY chain_seq',
                                    (enviada['id'], carta['id'])).fetchall()
        self.assertEqual((carta['signature_provider'], carta['accepted_by'].__str__()), ('mifiel', USER))
        self.assertEqual(carta['signed_document_key'], fila['signed_document_key'])
        self.assertEqual(carta['evidence_key'], fila['evidence_key'])
        self.assertIsNotNone(carta['signed_at'])
        self.assertEqual([a['action'] for a in acciones],
                         ['authorization.signature_requested', 'authorization.signature_signed',
                          'authorization.uploaded'])
        for a in acciones:
            self.assertNotIn('test@example.com', a['details'])
            self.assertNotIn('Nombre de prueba', a['details'])
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests/%s/accept' % enviada['id'],
                               {'confirm_fqdn': body['fqdn']}).status_code, 409)
        lista = pedir(self.app, 'GET', '/api/v1/signature-requests').json()
        self.assertEqual(lista['mode'], 'production')
        item = next(i for i in lista['items'] if i['id'] == enviada['id'])
        # Confirmada, el firmante ya no sale en la lista ni en la respuesta de accept (base-2).
        for solicitud in (item, datos['signature_request']):
            self.assertEqual((solicitud['signer_name'], solicitud['signer_title'], solicitud['signer_email']),
                             (None, None, None))
        self.assertNotIn('test@example.com', json.dumps(lista))

    def test_2_otra_empresa_no_la_ve(self):
        enviada = self.enviar()
        self.como.return_value = self.otro
        for accion, body in (('refresh', None), ('cancel', None), ('accept', {'confirm_fqdn': enviada['fqdn']})):
            with self.subTest(accion=accion):
                r = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/%s' % (enviada['id'], accion), body)
                self.assertEqual(r.status_code, 404)
        self.assertNotIn(enviada['id'], [i['id'] for i in pedir(self.app, 'GET', '/api/v1/signature-requests').json()['items']])
        self.assertIsNone(self.fila(enviada['id'], OTHER_ORG))
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests/no-es-uuid/refresh').status_code, 404)

    def test_3_cancelar_rechazar_vencer_y_fallar(self):
        cancelada = self.enviar()
        doc = self.fila(cancelada['id'])['provider_document_id']
        r = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/cancel' % cancelada['id'])
        self.assertEqual((r.status_code, r.json()['status']), (200, 'cancelled'))
        self.assertTrue(self.mifiel.docs[doc]['borrado'])
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests/%s/cancel' % cancelada['id']).status_code,
                         409)

        rechazada = self.enviar()
        self.mifiel.docs[self.fila(rechazada['id'])['provider_document_id']]['estado'] = {'state': 'rejected'}
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % rechazada['id']).json()['status'],
                         'rejected')

        vencida = self.enviar()
        self.mifiel.docs[self.fila(vencida['id'])['provider_document_id']]['borrado'] = True
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % vencida['id']).json()['status'],
                         'expired')

        self.mifiel.crear_falla = http_error(422)
        body = self.body()
        fallida = pedir(self.app, 'POST', '/api/v1/signature-requests', body)
        self.assertEqual(fallida.status_code, 502)
        self.assertNotIn('test@example.com', fallida.text)
        with transaction(ORG) as conn:
            fila = conn.execute('SELECT status, last_error FROM signature_requests WHERE fqdn = %s',
                                (body['fqdn'],)).fetchone()
        self.assertEqual(fila['status'], 'failed')
        self.mifiel.crear_falla, self.mifiel.hash_distinto = None, True
        # Una fallida no bloquea otra al mismo dominio. Si Mifiel recibió otro archivo, se borra allá y queda failed.
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests', body).status_code, 502)
        self.assertIn(('DELETE', 'documents/%s' % list(self.mifiel.docs)[-1]), self.mifiel.llamadas)

    def test_4_camino_a_y_renovacion_por_el_camino_b(self):
        self.produccion()
        body = {**self.body(), 'xml_base64': base64.b64encode(XML).decode()}
        r = pedir(self.app, 'POST', '/api/v1/signature-uploads', body)
        self.assertEqual(r.status_code, 201, r.text)
        domain_id = r.json()['domain']['id']
        with transaction(ORG) as conn:
            carta = conn.execute('SELECT * FROM domain_authorizations WHERE domain_id = %s', (domain_id,)).fetchone()
        self.assertEqual((carta['signature_provider'], carta['signature_request_id'], carta['signed_at']),
                         ('mifiel', None, None))
        self.assertEqual(self.descifrar(carta['evidence_key'], ORG, domain_id), XML)
        self.assertEqual(self.descifrar(carta['signed_document_key'], ORG, domain_id), PDF)
        malo = {**self.body(), 'xml_base64': base64.b64encode(b'<!DOCTYPE a [<!ENTITY b "c">]><a>&b;</a>').decode()}
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-uploads', malo).status_code, 422)
        self.assertEqual(self.mifiel.llamadas, [])

        # El mismo dominio renueva su carta por la API: otra fila de domain_authorizations, el mismo dominio.
        enviada = self.enviar(self.body(body['fqdn'], valid_from='2021-01-01'))
        self.mifiel.firmar(self.fila(enviada['id'])['provider_document_id'])
        pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % enviada['id'])
        ok = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/accept' % enviada['id'], {'confirm_fqdn': body['fqdn']})
        self.assertEqual((ok.status_code, ok.json()['domain']['id']), (200, domain_id), ok.text)
        with transaction(ORG) as conn:
            cartas_ = conn.execute('SELECT id::text, revoked_at IS NULL AS vigente FROM domain_authorizations '
                                   'WHERE domain_id = %s ORDER BY created_at', (domain_id,)).fetchall()
            # RC-272: la renovación revoca la carta anterior y lo deja en la bitácora, con la carta que la reemplaza.
            self.assertEqual([c['vigente'] for c in cartas_], [False, True])
            evento = conn.execute("SELECT actor_type, details->>'replaced_by' AS por FROM audit_log "
                                  "WHERE action = 'authorization.superseded' AND entity_id = %s",
                                  (cartas_[0]['id'],)).fetchall()
            self.assertEqual([(e['actor_type'], e['por']) for e in evento], [('system', cartas_[1]['id'])])
        # El alta de RC-59 sigue sin aceptar un dominio que ya existe.
        alta = {k: v for k, v in body.items() if k != 'xml_base64'}
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/domains', alta).status_code, 409)

    def test_5_la_base_no_deja_saltar_estados(self):
        self.produccion()
        enviada = self.enviar()
        rid = enviada['id']
        malos = (
            ("UPDATE signature_requests SET status = 'accepted', decided_by = %s, decided_at = now() WHERE id = %s",
             (USER, rid)),
            ("UPDATE signature_requests SET status = 'signed' WHERE id = %s", (rid,)),
            ("UPDATE signature_requests SET signer_name = 'Otro' WHERE id = %s", (rid,)),
            ("UPDATE signature_requests SET status = 'sent', provider_document_id = 'otro' WHERE id = %s", (rid,)),
            ('DELETE FROM signature_requests WHERE id = %s', (rid,)),
            ("INSERT INTO signature_requests (id, organization_id, provider, environment, fqdn, signer_name, "
             "signer_title, signer_email, valid_from, valid_until, template_version, activities, unsigned_document_key, "
             "unsigned_sha256, requested_by) VALUES (gen_random_uuid(), %s, 'mifiel', 'sandbox', 'x.example', 'a', 'b', "
             "'c@d.example', '2020-01-01', '2099-01-01', 1, '{1}', 'k', %s, %s)",
             (OTHER_ORG, b'\x00' * 32, OTHER_USER)),
        )
        for sql, args in malos:
            with self.subTest(sql=sql[:50]), self.assertRaises(psycopg.Error):
                with transaction(ORG) as conn:
                    conn.execute(sql, args)
        self.mifiel.firmar(self.fila(rid)['provider_document_id'])
        pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % rid)
        fila = self.fila(rid)
        # La carta tiene que copiar lo firmado: otro firmante, otro archivo o un dominio con otro fqdn no entran.
        subida = pedir(self.app, 'POST', '/api/v1/signature-uploads',
                       {**self.body(fila['fqdn']), 'xml_base64': base64.b64encode(XML).decode()})
        self.assertEqual(subida.status_code, 201, subida.text)
        dominio = subida.json()['domain']['id']
        with transaction(ORG) as conn:
            otro_dominio = conn.execute("SELECT id::text FROM domains WHERE status <> 'removed' AND fqdn <> %s LIMIT 1",
                                        (fila['fqdn'],)).fetchone()['id']
        base = [dominio, fila['signer_name'], fila['signer_title'], fila['signer_email'], fila['signed_document_key'],
                fila['signed_sha256'], fila['valid_from'], fila['valid_until'], USER, 1, fila['activities'], rid,
                'mifiel', fila['evidence_key'], fila['evidence_sha256'], fila['provider_signed_at']]
        insertar = ('INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, '
                    'signer_email, signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, '
                    'template_version, activities, signature_request_id, signature_provider, evidence_key, '
                    'evidence_sha256, signed_at) VALUES (%s, ' + ', '.join(['%s'] * 16) + ')')
        for indice, valor in ((0, otro_dominio), (1, 'Otra persona'), (5, b'\x01' * 32), (14, b'\x02' * 32),
                              (15, None), (13, None)):
            datos = list(base)
            datos[indice] = valor
            with self.subTest(columna=indice), self.assertRaises(psycopg.Error):
                with transaction(ORG) as conn:
                    conn.execute(insertar, (ORG, *datos))
        # Con los mismos datos sí entra: los rechazos de arriba son por la columna que cambió.
        with transaction(ORG) as conn:
            conn.execute(insertar, (ORG, *base))
        self.assertEqual(self.fila(rid)['status'], 'signed')

    def test_6_modo_distinto_o_apagado(self):
        enviada = self.enviar()
        with patch.dict(os.environ, {'FIRMA_MODO': 'produccion'}):
            r = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % enviada['id'])
            self.assertEqual(r.status_code, 409)
        with patch.dict(os.environ, {'FIRMA_MODO': 'apagado'}):
            antes = len(self.mifiel.llamadas)
            self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests', self.body()).status_code, 503)
            self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % enviada['id']).status_code,
                             503)
            self.assertEqual(len(self.mifiel.llamadas), antes)
            self.assertEqual(pedir(self.app, 'GET', '/api/v1/signature-requests').json()['mode'], 'off')

    def test_7_cancelar_con_otro_modo_o_apagado_libera_el_dominio(self):
        # tiempos_externa-3: antes cancel daba 409 o 503 y el dominio quedaba ocupado para siempre.
        for modo in ('produccion', 'apagado'):
            with self.subTest(modo=modo):
                body = self.body()
                enviada = self.enviar(body)
                doc = self.fila(enviada['id'])['provider_document_id']
                with patch.dict(os.environ, {'FIRMA_MODO': modo}):
                    antes = len(self.mifiel.llamadas)
                    cancelada = self.cancelar(enviada['id'])
                    self.assertEqual(len(self.mifiel.llamadas), antes)
                self.assertEqual(cancelada['status'], 'cancelled')
                self.assertIn('sin borrar en Mifiel', cancelada['last_error'])
                self.assertFalse(self.mifiel.docs[doc]['borrado'])
                self.assertIsNotNone(self.fila(enviada['id'])['decided_by'])
                # El dominio ya se puede mandar otra vez.
                self.cancelar(self.enviar(body)['id'])

    def test_8_una_carta_del_sandbox_no_se_confirma(self):
        # base-1: ni la API ni la base dejan que una firma del sandbox se vuelva autorización.
        body = self.body()
        enviada = self.enviar(body)
        self.assertEqual(enviada['environment'], 'sandbox')
        self.mifiel.firmar(self.fila(enviada['id'])['provider_document_id'])
        self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % enviada['id']).json()['status'],
                         'signed')
        for modo in ('sandbox', 'produccion', 'apagado'):
            with self.subTest(modo=modo), patch.dict(os.environ, {'FIRMA_MODO': modo}):
                r = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/accept' % enviada['id'],
                          {'confirm_fqdn': body['fqdn']})
                self.assertEqual(r.status_code, 409, r.text)
                self.assertIn('sandbox', r.json()['detail'])
        fila = self.fila(enviada['id'])
        self.assertEqual(fila['status'], 'signed')
        with transaction(ORG) as conn:
            self.assertIsNone(conn.execute('SELECT 1 FROM domains WHERE fqdn = %s', (body['fqdn'],)).fetchone())
        # Directo en la base, con un dominio del mismo fqdn y los mismos datos: el trigger lo rechaza por el entorno.
        subida = pedir(self.app, 'POST', '/api/v1/signature-uploads',
                       {**self.body(body['fqdn']), 'xml_base64': base64.b64encode(XML).decode()})
        self.assertEqual(subida.status_code, 201, subida.text)
        dominio = subida.json()['domain']['id']
        with self.assertRaises(psycopg.Error) as error:
            with transaction(ORG) as conn:
                conn.execute(
                    'INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, '
                    'signer_email, signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, '
                    'template_version, activities, signature_request_id, signature_provider, evidence_key, '
                    'evidence_sha256, signed_at) SELECT organization_id, %s, signer_name, signer_title, signer_email, '
                    'signed_document_key, signed_sha256, valid_from, valid_until, %s, template_version, activities, id, '
                    'provider, evidence_key, evidence_sha256, provider_signed_at FROM signature_requests WHERE id = %s',
                    (dominio, USER, enviada['id']))
        self.assertIn('no coincide con la solicitud firmada', str(error.exception))
        self.cancelar(enviada['id'])

    def test_9_sin_saber_si_mifiel_la_recibio_no_se_libera_sola(self):
        # sesion_datos-3 y tiempos_externa-1: plazo vencido, conexión cortada o un 5xx después de crear el documento.
        for falla in (transporte.PlazoVencido('x'), http.client.IncompleteRead(b'{"id"'), http_error(503)):
            with self.subTest(falla=type(falla).__name__):
                self.mifiel.crear_falla, self.mifiel.crear_despues = falla, True
                body = self.body()
                r = pedir(self.app, 'POST', '/api/v1/signature-requests', body)
                self.assertEqual(r.status_code, 502, r.text)
                self.assertIn('bórrala en la web de Mifiel', r.json()['detail'])
                self.assertNotIn('test@example.com', r.text)
                self.mifiel.crear_falla, self.mifiel.crear_despues = None, False
                with transaction(ORG) as conn:
                    fila = conn.execute('SELECT id::text, status, last_error, provider_document_id FROM '
                                        'signature_requests WHERE fqdn = %s', (body['fqdn'],)).fetchone()
                self.assertEqual((fila['status'], fila['provider_document_id']), ('creating', None))
                self.assertIn('Mifiel no confirmó', fila['last_error'])
                # No se manda una segunda invitación mientras siga abierta.
                antes = len(self.mifiel.llamadas)
                self.assertEqual(pedir(self.app, 'POST', '/api/v1/signature-requests', body).status_code, 409)
                self.assertEqual(len(self.mifiel.llamadas), antes)
                # refresh no la da por fallida: sigue igual y no llama a Mifiel.
                consulta = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % fila['id']).json()
                self.assertEqual(consulta['status'], 'creating')
                self.assertEqual(len(self.mifiel.llamadas), antes)
                # El Admin la cancela después de revisar en Mifiel y entonces sí se puede mandar otra.
                cancelada = self.cancelar(fila['id'])
                self.assertEqual(cancelada['status'], 'failed')
                self.assertIn('Cancelada sin confirmar en Mifiel', cancelada['last_error'])
                self.cancelar(self.enviar(body)['id'])

    def test_10_creating_sin_aviso(self):
        # La API se cayó a la mitad: la fila quedó en creating sin aviso. Recién creada no se cancela; vencida, refresh
        # le pone el aviso en vez de darla por fallida, y el Admin la cancela.
        rid = str(uuid.uuid4())
        with transaction(ORG) as conn:
            conn.execute(
                "INSERT INTO signature_requests (id, organization_id, provider, environment, fqdn, signer_name, "
                "signer_title, signer_email, valid_from, valid_until, template_version, activities, "
                "unsigned_document_key, unsigned_sha256, requested_by) VALUES (%s, %s, 'mifiel', 'sandbox', %s, 'a', "
                "'b', 'test@example.com', '2020-01-01', '2099-01-01', 1, '{1}', 'CIRDAN_FAKE_k', %s, %s)",
                (rid, ORG, 'cirdan-fake-firma-%s.example' % uuid.uuid4().hex[:10], b'\x00' * 32, USER))
        r = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/cancel' % rid)
        self.assertEqual(r.status_code, 409, r.text)
        with patch.object(firmas, 'CREANDO_VENCIDA', 0):
            consulta = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % rid).json()
            self.assertEqual(consulta['status'], 'creating')
            self.assertEqual(consulta['last_error'], firmas.INCIERTO)
        self.assertEqual(self.cancelar(rid)['status'], 'failed')
        self.assertEqual(self.mifiel.llamadas, [])

    def test_11_las_abiertas_de_dominios_nuevos_cuentan_para_el_tope(self):
        # tiempos_externa-5: el tope es el número de dominios más las solicitudes abiertas de fqdn que no existen.
        original = firmas._revisar_empresa_y_carta
        with transaction(ORG) as conn:
            ocupados = conn.execute(
                "SELECT (SELECT count(*) FROM domains WHERE status <> 'removed') + (SELECT count(DISTINCT s.fqdn) "
                "FROM signature_requests s WHERE s.status IN ('creating', 'sent', 'signed') AND NOT EXISTS "
                "(SELECT 1 FROM domains d WHERE d.fqdn = s.fqdn AND d.status <> 'removed')) AS n").fetchone()['n']
            existente = conn.execute("SELECT fqdn::text FROM domains WHERE status <> 'removed' AND NOT EXISTS "
                                     "(SELECT 1 FROM signature_requests s WHERE s.fqdn = domains.fqdn AND s.status IN "
                                     "('creating', 'sent', 'signed')) LIMIT 1").fetchone()['fqdn']
        with patch.object(firmas, '_revisar_empresa_y_carta',
                          side_effect=lambda conn, session, end: (original(conn, session, end), ocupados + 1)[1]):
            primera = self.enviar()
            antes = len(self.mifiel.llamadas)
            r = pedir(self.app, 'POST', '/api/v1/signature-requests', self.body())
            self.assertEqual((r.status_code, r.json()['detail']), (409, 'La organización alcanzó su límite de dominios.'))
            self.assertEqual(len(self.mifiel.llamadas), antes)
            # Un dominio que ya existe no ocupa otro lugar: su renovación sí se manda.
            renovacion = self.enviar(self.body(existente))
        self.cancelar(primera['id'])
        self.cancelar(renovacion['id'])

    def test_12_una_carta_futura_con_otra_vigente_da_409_sin_guardar_nada(self):
        """RC-272: por los dos caminos, una carta que empieza después de hoy no entra mientras el dominio tenga otra
        vigente. Da 409 antes de guardar el PDF y la carta firmada en Mifiel sigue 'signed' para confirmarla el día
        que empieza."""
        self.produccion()
        body = {**self.body(), 'xml_base64': base64.b64encode(XML).decode()}
        r = pedir(self.app, 'POST', '/api/v1/signature-uploads', body)
        self.assertEqual(r.status_code, 201, r.text)
        domain_id = r.json()['domain']['id']
        with transaction(ORG) as conn:
            manana = conn.execute('SELECT (current_date + 1)::text AS d').fetchone()['d']
        archivos = sorted(Path(self.dir.name).rglob('*'))

        futura = {**self.body(body['fqdn'], valid_from=manana), 'xml_base64': body['xml_base64']}
        r = pedir(self.app, 'POST', '/api/v1/signature-uploads', futura)
        self.assertEqual((r.status_code, r.json()['detail']), (409, v1.CARTA_FUTURA))
        self.assertEqual(sorted(Path(self.dir.name).rglob('*')), archivos)

        enviada = self.enviar(self.body(body['fqdn'], valid_from=manana))
        # Se puede mandar a firmar, y la solicitud dice desde cuándo se confirma (concurrencia-api-2).
        self.assertEqual(enviada['accept_from'], manana)
        self.mifiel.firmar(self.fila(enviada['id'])['provider_document_id'])
        pedir(self.app, 'POST', '/api/v1/signature-requests/%s/refresh' % enviada['id'])
        archivos = sorted(Path(self.dir.name).rglob('*'))
        r = pedir(self.app, 'POST', '/api/v1/signature-requests/%s/accept' % enviada['id'], {'confirm_fqdn': body['fqdn']})
        self.assertEqual((r.status_code, r.json()['detail']), (409, v1.CARTA_FUTURA))
        self.assertEqual(self.fila(enviada['id'])['status'], 'signed')
        self.assertEqual(sorted(Path(self.dir.name).rglob('*')), archivos)
        lista = pedir(self.app, 'GET', '/api/v1/signature-requests').json()
        self.assertEqual(next(s['accept_from'] for s in lista['items'] if s['id'] == enviada['id']), manana)
        with transaction(ORG) as conn:
            self.assertEqual(conn.execute('SELECT count(*) AS n FROM domain_authorizations WHERE domain_id = %s AND '
                                          'revoked_at IS NULL', (domain_id,)).fetchone()['n'], 1)
        self.cancelar(enviada['id'])


if __name__ == '__main__':
    unittest.main()

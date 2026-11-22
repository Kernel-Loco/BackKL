"""Integración HTTP y PostgreSQL del alta. Solo para una base de pruebas aislada."""
import base64
import asyncio
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI
from psycopg.errors import UniqueViolation

from cirdan.api import v1
from cirdan.auth.deps import Session
from cirdan.db import transaction
from cirdan.orquestador.txt import ConsultaTxt

ORG = '20000000-0000-4000-8000-000000000002'
USER = '30000000-0000-4000-8000-000000000004'
OTHER_ORG = '20000000-0000-4000-8000-000000000001'
OTHER_USER = '30000000-0000-4000-8000-000000000001'
# LowTide (semilla 015), plan business con lugar: Acme está en su tope de 5 y daría 409 por el límite.
THIRD_ORG = '20000000-0000-4000-8000-000000000004'
THIRD_USER = '30000000-0000-4000-8000-000000000006'
PDF = b'%PDF-1.4\nCIRDAN_FAKE_documento\n%%EOF\n'
KEY = b'c' * 32


def post(app, path, body=None):
    async def call():
        payload = json.dumps(body).encode() if body is not None else b''
        messages = []
        sent = False

        async def receive():
            nonlocal sent
            if sent:
                return {'type': 'http.disconnect'}
            sent = True
            return {'type': 'http.request', 'body': payload, 'more_body': False}

        async def send(message):
            messages.append(message)

        scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': 'POST',
                 'scheme': 'http', 'path': path, 'raw_path': path.encode(), 'query_string': b'',
                 'headers': [(b'content-type', b'application/json')], 'client': ('127.0.0.1', 1234),
                 'server': ('test', 80)}
        await app(scope, receive, send)
        status = next(m['status'] for m in messages if m['type'] == 'http.response.start')
        text = b''.join(m.get('body', b'') for m in messages if m['type'] == 'http.response.body').decode()
        return SimpleNamespace(status_code=status, text=text, json=lambda: json.loads(text))
    return asyncio.run(call())


@unittest.skipUnless(os.environ.get('CIRDAN_TEST_DB_ISOLATED') == 'true', 'Requiere una base de pruebas aislada')
class AltaIntegracion(unittest.TestCase):
    def test_alta_y_verificacion(self):
        admin = Session('CIRDAN_FAKE_session', USER, ORG, 'admin', 'test@example.com')
        other = Session('CIRDAN_FAKE_session', OTHER_USER, OTHER_ORG, 'admin', 'otro@example.com')
        third = Session('CIRDAN_FAKE_session', THIRD_USER, THIRD_ORG, 'admin', 'tercero@example.com')
        app = FastAPI()
        app.include_router(v1.router)
        body = {
            'fqdn': 'cirdan-fake-test.example', 'signer_name': 'Nombre de prueba', 'signer_title': 'Representante',
            'signer_email': 'test@example.com', 'valid_from': '2020-01-01', 'valid_until': '2099-01-01',
            'passive_monitoring_confirmed': True, 'letter_base64': base64.b64encode(PDF).decode(),
            'template_version': 1, 'activities': [2, 1, 6],
        }
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'CARTA_ALTA_ENABLED': 'true', 'COOKIE_SECURE': 'false',
                                        'CARTA_STORAGE_DIR': directory}), \
                patch('cirdan.auth.deps.current_session', return_value=admin) as session, \
                patch('cirdan.cartas._key', return_value=KEY), \
                patch.object(v1, 'client_ip', return_value='127.0.0.1'), \
                patch.object(v1.orquestador, 'en_vivo_permitido', return_value=True), \
                patch.object(v1.dns_txt, 'consultar_dns') as dns:
            with patch('cirdan.cartas.guardar', side_effect=OSError('CIRDAN_FAKE_STORAGE_FAILURE')):
                with self.assertRaises(OSError):
                    post(app, '/api/v1/domains', body)
            with transaction(ORG) as conn:
                self.assertEqual(conn.execute('SELECT count(*) AS total FROM domains WHERE fqdn = %s',
                                              (body['fqdn'],)).fetchone()['total'], 0)
            # Una carta vencida (fin antes de hoy en México) se rechaza y no deja dominio (RC-59).
            vencida = post(app, '/api/v1/domains', {**body, 'valid_from': '2020-01-01', 'valid_until': '2020-12-31'})
            self.assertEqual((vencida.status_code, vencida.json()['detail']), (422, 'La carta ya está vencida.'))
            with transaction(ORG) as conn:
                self.assertEqual(conn.execute('SELECT count(*) AS total FROM domains WHERE fqdn = %s',
                                              (body['fqdn'],)).fetchone()['total'], 0)
            response = post(app, '/api/v1/domains', body)
            self.assertEqual(response.status_code, 201, response.text)
            data = response.json()
            domain_id = data['domain']['id']
            self.assertEqual((data['domain']['status'], data['domain']['scan_eligibility']['can_scan']),
                             ('pending_verification', False))
            with transaction(ORG) as conn:
                row = conn.execute('SELECT signed_document_key, signed_document_sha256, template_version, activities '
                                   'FROM domain_authorizations WHERE domain_id = %s', (domain_id,)).fetchone()
            self.assertEqual(bytes(row['signed_document_sha256']), hashlib.sha256(PDF).digest())
            self.assertEqual((row['template_version'], row['activities']), (1, [1, 2, 6]))
            self.assertEqual((data['domain']['authorization']['template_version'],
                              data['domain']['authorization']['activities']), (1, [1, 2, 6]))
            blob = (Path(directory) / row['signed_document_key']).read_bytes()
            self.assertNotIn(PDF, blob)
            associated = ('%s:%s:%s' % (ORG, domain_id, row['signed_document_key'])).encode()
            self.assertEqual(AESGCM(KEY).decrypt(blob[3:15], blob[15:], associated), PDF)

            self.assertEqual(post(app, '/api/v1/domains', body).status_code, 409)
            session.return_value = other
            self.assertEqual(post(app, '/api/v1/domains/cirdan-fake-test.example/txt/verify').status_code, 404)
            dns.assert_not_called()
            # Acme ya está en su tope: una carta vencida da 422 antes que el 409 del límite (RC-59, api-3).
            tope = {**body, 'fqdn': 'cirdan-fake-tope.example'}
            vencida = post(app, '/api/v1/domains', {**tope, 'valid_until': '2020-12-31'})
            self.assertEqual((vencida.status_code, vencida.json()['detail']), (422, 'La carta ya está vencida.'))
            limite = post(app, '/api/v1/domains', tope)
            self.assertEqual((limite.status_code, limite.json()['detail']),
                             (409, 'La organización alcanzó su límite de dominios.'))
            # Otra empresa puede tenerlo pendiente mientras nadie lo verifica: gana la primera que publica el TXT.
            otro_token = 'cirdanfaketokenotraempresa59'
            with transaction(OTHER_ORG) as conn:
                otro_id = conn.execute(
                    "INSERT INTO domains (organization_id, fqdn, status, txt_token, added_by) "
                    "VALUES (%s, %s, 'pending_verification', %s, %s) RETURNING id::text",
                    (OTHER_ORG, body['fqdn'], otro_token, OTHER_USER)).fetchone()['id']

            def dar_de_baja_el_de_acme():
                # Acme queda en su tope de 5 sin este dominio aunque falle un assert de en medio (test_3c4).
                with transaction(OTHER_ORG) as conn:
                    conn.execute("UPDATE domains SET status = 'removed' WHERE id = %s", (otro_id,))
            self.addCleanup(dar_de_baja_el_de_acme)
            with transaction(OTHER_ORG) as conn:
                conn.execute(
                    'INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, '
                    'signer_email, signed_document_key, signed_document_sha256, valid_from, valid_until, '
                    'accepted_by, template_version, activities) '
                    "VALUES (%s, %s, 'Nombre de prueba', 'Representante', 'otro@example.com', "
                    "'CIRDAN_FAKE_carta_otra_empresa', %s, '2020-01-01', '2099-01-01', %s, 1, %s)",
                    (OTHER_ORG, otro_id, hashlib.sha256(PDF).digest(), OTHER_USER, list(range(1, 12))))
            session.return_value = admin
            dns.return_value = ConsultaTxt(None)
            missing = post(app, '/api/v1/domains/cirdan-fake-test.example/txt/verify')
            self.assertEqual(missing.status_code, 200, missing.text)
            self.assertEqual(missing.json()['domain']['status'], 'pending_verification')
            dns.return_value = ConsultaTxt((data['txt']['expected_value'],))
            verified = post(app, '/api/v1/domains/cirdan-fake-test.example/txt/verify')
            self.assertEqual(verified.status_code, 200, verified.text)
            self.assertEqual((verified.json()['domain']['status'], verified.json()['txt']['status']),
                             ('verified', 'verified'))
            with transaction(ORG) as conn:
                result = conn.execute("SELECT status, verified_at FROM domains WHERE id = %s", (domain_id,)).fetchone()
                audits = conn.execute("SELECT action FROM audit_log WHERE entity_id = %s ORDER BY chain_seq",
                                      (domain_id,)).fetchall()
            self.assertEqual(result['status'], 'verified')
            self.assertIsNotNone(result['verified_at'])
            self.assertEqual([x['action'] for x in audits], ['domain.added', 'domain.txt_checked', 'domain.txt_checked'])

            # Ya verificado en ORG: otra empresa no lo verifica ni lo da de alta, aunque por RLS no lo vea.
            with self.assertRaises(UniqueViolation) as error, transaction(OTHER_ORG) as conn:
                conn.execute("UPDATE domains SET status = 'verified', verified_at = now() WHERE id = %s", (otro_id,))
            self.assertEqual(error.exception.diag.constraint_name, 'domains_fqdn_otra_organizacion')
            session.return_value = third
            with patch.object(v1.cartas, 'guardar') as guardar:
                ajeno = post(app, '/api/v1/domains', body)
            self.assertEqual((ajeno.status_code, ajeno.json()['detail']),
                             (409, 'El dominio ya está verificado por otra organización.'))
            guardar.assert_not_called()
            with transaction(THIRD_ORG) as conn:
                self.assertEqual(conn.execute('SELECT count(*) AS total FROM domains WHERE fqdn = %s',
                                              (body['fqdn'],)).fetchone()['total'], 0)

            # En pausa en ORG sigue siendo suyo: el índice único de 'verified' no lo cubre y el trigger sí.
            with transaction(ORG) as conn:
                conn.execute("UPDATE domains SET status = 'paused' WHERE id = %s", (domain_id,))
            ajeno = post(app, '/api/v1/domains', body)
            self.assertEqual(ajeno.status_code, 409, ajeno.text)
            # Acme publica su TXT correcto: 409, pero la consulta y su auditoría quedan (RC-59, concurrencia-2).
            session.return_value = other
            dns.return_value = ConsultaTxt((v1.dns_txt.esperado(otro_token),))
            choque = post(app, '/api/v1/domains/cirdan-fake-test.example/txt/verify')
            self.assertEqual((choque.status_code, choque.json()['detail']),
                             (409, 'El dominio ya está verificado por otra organización.'))
            with transaction(OTHER_ORG) as conn:
                self.assertEqual(conn.execute('SELECT status FROM domains WHERE id = %s', (otro_id,)).fetchone()['status'],
                                 'pending_verification')
                consultas = conn.execute('SELECT result FROM dns_txt_verifications WHERE domain_id = %s',
                                         (otro_id,)).fetchall()
                auditadas = conn.execute("SELECT details FROM audit_log WHERE entity_id = %s "
                                         "AND action = 'domain.txt_checked'", (otro_id,)).fetchall()
            self.assertEqual([x['result'] for x in consultas], ['match'])
            self.assertEqual([x['details'] for x in auditadas], [{'result': 'match', 'conflict': 'other_organization'}])
            session.return_value = admin
            with self.assertRaises(UniqueViolation), transaction(OTHER_ORG) as conn:
                conn.execute("UPDATE domains SET status = 'verified', verified_at = now() WHERE id = %s", (otro_id,))
            # Dado de baja ('removed') no choca: la de OTHER_ORG ya lo puede verificar y la baja de ORG sigue igual.
            with transaction(ORG) as conn:
                conn.execute("UPDATE domains SET status = 'removed' WHERE id = %s", (domain_id,))
            with transaction(OTHER_ORG) as conn:
                conn.execute("UPDATE domains SET status = 'verified', verified_at = now() WHERE id = %s", (otro_id,))
            with self.assertRaises(UniqueViolation), transaction(ORG) as conn:
                conn.execute("UPDATE domains SET status = 'paused' WHERE id = %s", (domain_id,))


if __name__ == '__main__':
    unittest.main()

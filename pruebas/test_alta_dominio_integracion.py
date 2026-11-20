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

from cirdan.api import v1
from cirdan.auth.deps import Session
from cirdan.db import transaction
from cirdan.orquestador.txt import ConsultaTxt

ORG = '20000000-0000-4000-8000-000000000002'
USER = '30000000-0000-4000-8000-000000000004'
OTHER_ORG = '20000000-0000-4000-8000-000000000001'
OTHER_USER = '30000000-0000-4000-8000-000000000001'
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
        app = FastAPI()
        app.include_router(v1.router)
        body = {
            'fqdn': 'cirdan-fake-test.example', 'signer_name': 'Nombre de prueba', 'signer_title': 'Representante',
            'signer_email': 'test@example.com', 'valid_from': '2020-01-01', 'valid_until': '2099-01-01',
            'passive_monitoring_confirmed': True, 'letter_base64': base64.b64encode(PDF).decode(),
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
            response = post(app, '/api/v1/domains', body)
            self.assertEqual(response.status_code, 201, response.text)
            data = response.json()
            domain_id = data['domain']['id']
            self.assertEqual((data['domain']['status'], data['domain']['scan_eligibility']['can_scan']),
                             ('pending_verification', False))
            with transaction(ORG) as conn:
                row = conn.execute('SELECT signed_document_key, signed_document_sha256 FROM domain_authorizations '
                                   'WHERE domain_id = %s', (domain_id,)).fetchone()
            self.assertEqual(bytes(row['signed_document_sha256']), hashlib.sha256(PDF).digest())
            blob = (Path(directory) / row['signed_document_key']).read_bytes()
            self.assertNotIn(PDF, blob)
            associated = ('%s:%s:%s' % (ORG, domain_id, row['signed_document_key'])).encode()
            self.assertEqual(AESGCM(KEY).decrypt(blob[3:15], blob[15:], associated), PDF)

            self.assertEqual(post(app, '/api/v1/domains', body).status_code, 409)
            session.return_value = other
            self.assertEqual(post(app, '/api/v1/domains/cirdan-fake-test.example/txt/verify').status_code, 404)
            dns.assert_not_called()
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


if __name__ == '__main__':
    unittest.main()

"""Alta de dominio y almacenamiento de cartas, sin consultas de red."""
import asyncio
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException
from starlette.requests import Request

from cirdan import cartas
from cirdan.api import v1
from cirdan.auth.deps import Session


PDF = b'%PDF-1.4\nCIRDAN_FAKE_documento\n%%EOF\n'
KEY = b'c' * 32
BODY = {
    'fqdn': 'EJEMPLO.COM.', 'signer_name': 'Nombre de prueba', 'signer_title': 'Representante',
    'signer_email': 'test@example.com', 'valid_from': '2026-01-01', 'valid_until': '2027-01-01',
    'passive_monitoring_confirmed': True, 'letter_base64': base64.b64encode(PDF).decode(),
}


class AltaDominio(unittest.TestCase):
    def test_valida_y_normaliza(self):
        fqdn, name, title, email, start, end, pdf = v1._datos_alta(BODY)
        self.assertEqual((fqdn, name, title, email), ('ejemplo.com', 'Nombre de prueba', 'Representante', 'test@example.com'))
        self.assertLess(start, end)
        self.assertEqual(pdf, PDF)

    def test_rechaza_datos_invalidos(self):
        for update in ({'fqdn': 'https://ejemplo.com'}, {'signer_name': ''}, {'signer_title': ''},
                       {'signer_email': 'mal'}, {'valid_until': '2025-01-01'}, {'valid_from': 'no-fecha'},
                       {'passive_monitoring_confirmed': False}, {'letter_base64': '!!'},
                       {'letter_base64': base64.b64encode(b'no es pdf').decode()}):
            with self.subTest(update=update), self.assertRaises(HTTPException) as error:
                v1._datos_alta({**BODY, **update})
            self.assertEqual(error.exception.status_code, 422)

    def test_pdf_mayor_a_cinco_mib_se_rechaza(self):
        too_big = base64.b64encode(b'%PDF-' + b'x' * v1.MAX_CARTA + b'%%EOF').decode()
        with self.assertRaises(HTTPException) as error:
            v1._datos_alta({**BODY, 'letter_base64': too_big})
        self.assertEqual(error.exception.status_code, 413)

    def test_pdf_de_cinco_mib_se_acepta(self):
        pdf = b'%PDF-' + b'x' * (v1.MAX_CARTA - 10) + b'%%EOF'
        self.assertEqual(len(pdf), v1.MAX_CARTA)
        self.assertEqual(v1._datos_alta({**BODY, 'letter_base64': base64.b64encode(pdf).decode()})[-1], pdf)

    def test_no_habilita_en_produccion(self):
        with patch.object(cartas, 'config', side_effect=lambda name, default=None: {
                'CARTA_ALTA_ENABLED': 'true', 'COOKIE_SECURE': 'true'}.get(name, default)):
            self.assertFalse(cartas.habilitado())

    def test_sin_habilitar_no_lee_la_peticion(self):
        request = Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': []})
        session = Session(token='', user_id='user', org_id='org', role='admin', email='a@example.com')
        with patch.object(cartas, 'habilitado', return_value=False), self.assertRaises(HTTPException) as error:
            asyncio.run(v1.register_domain(request, session))
        self.assertEqual(error.exception.status_code, 409)

    def test_carta_guardada_cifrada_y_ligada_a_empresa_y_dominio(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cartas, 'config', side_effect=lambda name, default=None: {
                'CARTA_STORAGE_DIR': directory}.get(name, default)), patch.object(cartas, '_key', return_value=KEY):
                filename, digest = cartas.guardar(PDF, 'org', 'domain')
                blob = (Path(directory) / filename).read_bytes()
                self.assertNotIn(PDF, blob)
                self.assertEqual(digest, hashlib.sha256(PDF).digest())
                associated = ('org:domain:' + filename).encode()
                self.assertEqual(AESGCM(KEY).decrypt(blob[3:15], blob[15:], associated), PDF)
                self.assertEqual((Path(directory) / filename).stat().st_mode & 0o777, 0o600)

    def test_llave_distinta_de_las_otras(self):
        encoded = base64.urlsafe_b64encode(KEY).decode()
        with patch.object(cartas, 'config', side_effect=lambda name, default=None: {
                'CARTA_ENCRYPTION_KEY': encoded}.get(name, default)), \
                patch.object(cartas.totp, 'comprobar_llave', return_value=KEY), \
                patch.object(cartas.passwords, '_key', return_value=b'p' * 32):
            with self.assertRaisesRegex(RuntimeError, 'distinta'):
                cartas._key()


if __name__ == '__main__':
    unittest.main()

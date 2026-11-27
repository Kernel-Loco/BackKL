"""Pruebas sin base ni red de la verificación TXT desde la API."""
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi import HTTPException
from psycopg.errors import UniqueViolation
from starlette.requests import Request

from cirdan.api import v1
from cirdan.auth.deps import Session, require_roles
from cirdan.orquestador.txt import ConsultaTxt


FECHA = datetime(2026, 11, 19, tzinfo=timezone.utc)
DOMINIO = {'id': 'domain-id', 'fqdn': 'example.com', 'status': 'pending_verification', 'txt_token': 'ab12cd34ef56'}
# Un token en hex, como los de secrets.token_hex: desde la 037 (RC-272) solo ese se guarda tal cual en observed_values
ESPERADO = 'cirdan-verification=ab12cd34ef56'


class Cursor:
    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return self.value

    def fetchall(self):
        return self.value


class Connection:
    def __init__(self, domain=DOMINIO, conflict=False):
        self.domain = domain
        self.conflict = conflict
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if sql.startswith('SELECT id::text, fqdn::text'):
            return Cursor(self.domain)
        if sql.startswith('INSERT INTO dns_txt_verifications'):
            return Cursor({'checked_at': FECHA})
        if sql.startswith('UPDATE domains'):
            if self.conflict:
                raise UniqueViolation()
            return Cursor(None)
        if sql == v1.DOMAINS_SQL:
            return Cursor([{'id': 'domain-id'}])
        raise AssertionError(sql)

    @contextmanager
    def transaction(self):
        yield


class VerificacionTxtApi(unittest.TestCase):
    def setUp(self):
        self.session = Session(token='CIRDAN_FAKE_session', user_id='user-id', org_id='org-id',
                               role='admin', email='admin@example.com')
        self.request = Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': [],
                                'client': ('127.0.0.1', 1234)})
        self.conn = Connection()

        @contextmanager
        def transaction(org):
            self.assertEqual(org, 'org-id')
            yield self.conn

        self.patches = [
            patch.object(v1, 'transaction', transaction),
            patch.object(v1, 'audit'),
            patch.object(v1, '_domain', side_effect=lambda row: row),
            patch.object(v1.orquestador, '_motivos_previos', return_value=([], 'auth-id')),
            patch.object(v1.orquestador, 'en_vivo_permitido', return_value=True),
            patch.object(v1.dns_txt, 'consultar_dns'),
        ]
        self.mocks = [p.start() for p in self.patches]
        self.addCleanup(self.stop_patches)

    def stop_patches(self):
        for p in reversed(self.patches):
            p.stop()

    def check(self, consulta):
        self.mocks[-1].return_value = consulta
        return v1.verify_domain_txt('EXAMPLE.COM.', self.request, self.session)

    def test_match_activa_pendiente_y_devuelve_txt(self):
        result = self.check(ConsultaTxt((ESPERADO, 'secreto-ajeno')))
        self.assertEqual(result['txt'], {'fqdn': 'example.com', 'status': 'verified',
                                         'expected_value': ESPERADO, 'checked_at': FECHA})
        insert = next(params for sql, params in self.conn.calls if sql.startswith('INSERT INTO dns_txt_verifications'))
        self.assertEqual(insert[4], [ESPERADO])
        self.assertEqual(insert[6], 'match')
        self.assertTrue(any(sql.startswith('UPDATE domains') for sql, _ in self.conn.calls))
        self.mocks[-1].assert_called_once_with('example.com')

    def test_txt_no_coincide_no_activa_dominio(self):
        result = self.check(ConsultaTxt(('otro',)))
        self.assertEqual(result['txt']['status'], 'missing')
        insert = next(params for sql, params in self.conn.calls if sql.startswith('INSERT INTO dns_txt_verifications'))
        self.assertEqual((insert[4], insert[6]), (None, 'mismatch'))
        self.assertFalse(any(sql.startswith('UPDATE domains') for sql, _ in self.conn.calls))

    def test_txt_ausente_no_activa_dominio(self):
        result = self.check(ConsultaTxt(None))
        self.assertEqual(result['txt']['status'], 'missing')
        insert = next(params for sql, params in self.conn.calls if sql.startswith('INSERT INTO dns_txt_verifications'))
        self.assertEqual(insert[6], 'missing')
        self.assertFalse(any(sql.startswith('UPDATE domains') for sql, _ in self.conn.calls))

    def test_dns_error_es_explicito_y_no_activa(self):
        with self.assertRaises(HTTPException) as error:
            self.check(ConsultaTxt(None, error='timeout'))
        self.assertEqual(error.exception.status_code, 503)
        self.assertFalse(any(sql.startswith('UPDATE domains') for sql, _ in self.conn.calls))
        self.assertTrue(self.mocks[1].called)

    def test_dominio_ajeno_no_consulta_dns(self):
        self.conn.domain = None
        with self.assertRaises(HTTPException) as error:
            self.check(ConsultaTxt((ESPERADO,)))
        self.assertEqual(error.exception.status_code, 404)
        self.mocks[-1].assert_not_called()

    def test_sin_autorizacion_no_consulta_dns(self):
        self.mocks[3].return_value = (['authorization_missing'], None)
        with self.assertRaises(HTTPException) as error:
            self.check(ConsultaTxt((ESPERADO,)))
        self.assertEqual(error.exception.status_code, 409)
        self.mocks[-1].assert_not_called()

    def test_dominio_pausado_no_consulta_dns(self):
        self.mocks[3].return_value = (['domain_paused'], 'auth-id')
        with self.assertRaises(HTTPException) as error:
            self.check(ConsultaTxt((ESPERADO,)))
        self.assertEqual(error.exception.status_code, 409)
        self.mocks[-1].assert_not_called()

    def test_fuera_de_la_lista_no_consulta_dns(self):
        self.mocks[4].return_value = False
        with self.assertRaises(HTTPException) as error:
            self.check(ConsultaTxt((ESPERADO,)))
        self.assertEqual(error.exception.status_code, 403)
        self.mocks[-1].assert_not_called()

    def test_dominio_verificado_no_se_reactiva(self):
        self.conn.domain = {**DOMINIO, 'status': 'verified'}
        result = self.check(ConsultaTxt((ESPERADO,)))
        self.assertEqual(result['txt']['status'], 'verified')
        self.assertFalse(any(sql.startswith('UPDATE domains') for sql, _ in self.conn.calls))

    def test_dominio_ya_verificado_en_otra_empresa(self):
        self.conn.conflict = True
        with self.assertRaises(HTTPException) as error:
            self.check(ConsultaTxt((ESPERADO,)))
        self.assertEqual(error.exception.status_code, 409)
        # La consulta y su auditoría se guardan con el choque; el 409 sale después del commit (RC-59, concurrencia-2).
        self.mocks[1].assert_called_once()
        self.assertEqual(self.mocks[1].call_args.args[7], {'result': 'match', 'conflict': 'other_organization'})

    def test_rol_no_admin_no_puede_verificar(self):
        with patch('cirdan.auth.deps.current_session', return_value=Session(
                token='CIRDAN_FAKE_session', user_id='user-id', org_id='org-id', role='analyst',
                email='analyst@example.com')):
            with self.assertRaises(HTTPException) as error:
                require_roles('admin')(self.request)
        self.assertEqual(error.exception.status_code, 403)


if __name__ == '__main__':
    unittest.main()

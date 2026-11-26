"""Fin del servicio y cancelación de cuentas (#140, RC-258) contra el compose desechable.

    python -m unittest -v pruebas/test_fin_servicio.py      (con el compose desechable y CIRDAN_RETENTION_PASSWORD en .env)

Siembra una empresa propia de la prueba con un dominio, su carta y su TXT, un escaneo, activos padre e hijo, hallazgos
(uno resuelto con su brecha), un score con su aporte, una alerta con su entrega, un reporte y una llave. Corre los
comandos del operador dentro del contenedor de la API y revisa que se borre lo de la empresa y nada de las demás, que la
carta, el TXT y la bitácora sigan, y que la cuenta cancelada pierda su huella y su TOTP y se anonimice al vencer el plazo.
"""
import subprocess
import unittest

from pruebas.pila import exigir_desechable
from pruebas.test_aislamiento import ACME, psql, scalar
from pruebas.test_retencion import API, contrasena


def uid(n):
    return 'e1400000-0000-4000-8000-%012d' % n


ORG, ADMIN, ANA, DOM, AUT, TXT, SCAN, RUN = (uid(i) for i in range(1, 9))
RAIZ_, HIJO, F_ABIERTO, F_RESUELTO, SCORE, APORTE, INTEG, ALERTA, ENTREGA, REPORTE = (uid(i) for i in range(9, 19))
HASH_DE_RELLENO = '$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0$ZGVtby1vbmx5'   # cirdan/auth/demo.py
REGLA = ("(SELECT id FROM scoring_rules WHERE rule_set_id = '90000000-0000-4000-8000-000000000001' "
         "AND code = 'breach_exposure')")
FUENTE = "(SELECT id FROM data_sources WHERE code = 'dns')"

SEMBRAR = """
BEGIN;
SET LOCAL session_replication_role = replica;
INSERT INTO organizations (id, name, plan_id, status) VALUES ('{ORG}', 'RC-258 prueba', '10000000-0000-4000-8000-000000000002', 'active');
INSERT INTO users (id, organization_id, email, full_name, role, password_hash, totp_secret_enc, mfa_enabled_at)
VALUES ('{ADMIN}', '{ORG}', 'admin@rc258.invalid', 'Admin Prueba', 'admin', '$argon2id$prueba', '\\x01', now()),
       ('{ANA}', '{ORG}', 'ana@rc258.invalid', 'Ana Prueba', 'analyst', '$argon2id$prueba', '\\x02', now());
INSERT INTO domains (id, organization_id, fqdn, status, txt_token) VALUES ('{DOM}', '{ORG}', 'rc258.invalid', 'verified', 'rc258token');
INSERT INTO domain_authorizations (id, organization_id, domain_id, signer_name, signer_title, signer_email,
  signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by)
VALUES ('{AUT}', '{ORG}', '{DOM}', 'Firma Prueba', 'CISO', 'firma@rc258.invalid', 'rc258.pdf', sha256('rc258'),
        current_date - 30, current_date + 300, '{ADMIN}');
INSERT INTO dns_txt_verifications (id, organization_id, domain_id, check_reason, expected_value, resolver_ip, result, checked_at)
VALUES ('{TXT}', '{ORG}', '{DOM}', 'pre_scan', 'rc258token', '8.8.8.8', 'match', now());
INSERT INTO scans (id, organization_id, domain_id, authorization_id, txt_verification_id, trigger_type, status, finished_at)
VALUES ('{SCAN}', '{ORG}', '{DOM}', '{AUT}', '{TXT}', 'on_demand', 'completed', now());
INSERT INTO scan_source_runs (id, organization_id, scan_id, source_id, status) VALUES ('{RUN}', '{ORG}', '{SCAN}', {FUENTE}, 'succeeded');
INSERT INTO assets (id, organization_id, domain_id, parent_asset_id, asset_type, value, first_seen_at, last_seen_at)
VALUES ('{RAIZ_}', '{ORG}', '{DOM}', NULL, 'domain', 'rc258.invalid', now(), now()),
       ('{HIJO}', '{ORG}', '{DOM}', '{RAIZ_}', 'subdomain', 'www.rc258.invalid', now(), now());
INSERT INTO findings (id, organization_id, domain_id, asset_id, rule_id, source_id, fingerprint, severity, status,
                      evidence, detected_at, resolved_at, last_scan_id)
VALUES ('{F_ABIERTO}', '{ORG}', '{DOM}', '{HIJO}', {REGLA}, {FUENTE}, sha256('rc258-a'), 'critical', 'open', '{{}}', now(), NULL, '{SCAN}'),
       ('{F_RESUELTO}', '{ORG}', '{DOM}', '{RAIZ_}', {REGLA}, {FUENTE}, sha256('rc258-r'), 'high', 'resolved', '{{}}', now(), now(), '{SCAN}');
INSERT INTO breach_exposures (finding_id, organization_id, breach_name, data_classes) VALUES ('{F_RESUELTO}', '{ORG}', 'RC258', ARRAY['Email addresses']);
INSERT INTO domain_scores (id, organization_id, domain_id, scan_id, rule_set_id, score, category_scores, reason, computed_at)
VALUES ('{SCORE}', '{ORG}', '{DOM}', '{SCAN}', '90000000-0000-4000-8000-000000000001', 70, '{{}}', 'scan', now());
INSERT INTO score_contributions (id, organization_id, score_id, finding_id, rule_id, penalty, severity, factors)
VALUES ('{APORTE}', '{ORG}', '{SCORE}', '{F_ABIERTO}', {REGLA}, 10, 'critical', '{{}}');
INSERT INTO integrations (id, organization_id, kind, name, endpoint) VALUES ('{INTEG}', '{ORG}', 'webhook', 'RC-258', 'example.invalid');
INSERT INTO alerts (id, organization_id, domain_id, event_type, score_id, severity, payload, detected_at)
VALUES ('{ALERTA}', '{ORG}', '{DOM}', 'score.above_threshold', '{SCORE}', 'high', '{{}}', now());
INSERT INTO deliveries (id, organization_id, integration_id, alert_id, status, message_id, detected_at)
VALUES ('{ENTREGA}', '{ORG}', '{INTEG}', '{ALERTA}', 'delivered', 'rc258-{ENTREGA}', now());
INSERT INTO reports (id, organization_id, domain_id, kind, period_start, period_end, status)
VALUES ('{REPORTE}', '{ORG}', '{DOM}', 'pdf_report', current_date - 7, current_date, 'ready');
INSERT INTO api_keys (organization_id, name, key_prefix, key_hash, scopes, created_by, expires_at)
VALUES ('{ORG}', 'CIRDAN_FAKE_258', 'lt_ffff0258', sha256('CIRDAN_FAKE_258'::bytea), '{{read}}', '{ADMIN}', now() + interval '1 day');
COMMIT;
"""

LIMPIAR = """
BEGIN;
SET LOCAL session_replication_role = replica;
DELETE FROM deliveries WHERE organization_id = '{ORG}'; DELETE FROM alerts WHERE organization_id = '{ORG}';
DELETE FROM integrations WHERE organization_id = '{ORG}'; DELETE FROM score_contributions WHERE organization_id = '{ORG}';
DELETE FROM domain_scores WHERE organization_id = '{ORG}'; DELETE FROM breach_exposures WHERE organization_id = '{ORG}';
DELETE FROM findings WHERE organization_id = '{ORG}'; DELETE FROM assets WHERE organization_id = '{ORG}';
DELETE FROM reports WHERE organization_id = '{ORG}'; DELETE FROM scan_source_runs WHERE organization_id = '{ORG}';
DELETE FROM scans WHERE organization_id = '{ORG}'; DELETE FROM dns_txt_verifications WHERE organization_id = '{ORG}';
DELETE FROM domain_authorizations WHERE organization_id = '{ORG}'; DELETE FROM domains WHERE organization_id = '{ORG}';
DELETE FROM api_keys WHERE organization_id = '{ORG}'; DELETE FROM webauthn_credentials WHERE organization_id = '{ORG}';
DELETE FROM audit_log WHERE organization_id = '{ORG}'; DELETE FROM users WHERE organization_id = '{ORG}';
DELETE FROM organizations WHERE id = '{ORG}';
COMMIT;
"""


def valores():
    return {k: v for k, v in globals().items() if k.isupper() and isinstance(v, str)}


def comando(*args, con_contrasena=True):
    exigir_desechable()
    entorno = ['-e', 'CIRDAN_RETENTION_PASSWORD=' + contrasena()] if con_contrasena else []
    return subprocess.run(['docker', 'exec', *entorno, API, 'python', '-m', *args],
                          capture_output=True, text=True, encoding='utf-8', timeout=120)


def postgres(sql):
    ok, salida, err = psql(sql, user='postgres')
    if not ok:
        raise AssertionError(err)
    return salida


class FinDeServicio(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not contrasena():
            raise unittest.SkipTest('sin CIRDAN_RETENTION_PASSWORD (el CI la pone en .env)')

    def setUp(self):
        self.addCleanup(postgres, LIMPIAR.format(**valores()))
        postgres(LIMPIAR.format(**valores()))   # por si una corrida anterior se cortó
        postgres(SEMBRAR.format(**valores()))

    def contar(self, tabla):
        return int(scalar("SELECT count(*) FROM %s WHERE organization_id = '%s';" % (tabla, ORG), user='postgres'))

    def test_1_terminar_borra_lo_de_la_empresa_y_conserva_carta_txt_y_bitacora(self):
        acme_antes = scalar("SELECT count(*) FROM findings WHERE organization_id = '%s';" % ACME, user='postgres')
        # cirdan_app no borra scores, ni de una empresa que terminó
        ok, _, _ = psql("DELETE FROM domain_scores WHERE id = '%s';" % SCORE, org=ORG)
        self.assertFalse(ok)
        r = comando('cirdan.fin_servicio', 'terminar', ORG, '--motivo', 'Cierre del curso', '--sin-correo')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('servicio terminado: 12 filas borradas, 2 cuentas desactivadas, 1 llaves revocadas', r.stdout)
        for tabla in ('deliveries', 'alerts', 'score_contributions', 'domain_scores', 'breach_exposures', 'findings',
                      'assets', 'reports', 'scan_source_runs', 'scans'):
            with self.subTest(tabla=tabla):
                self.assertEqual(self.contar(tabla), 0)
        for tabla in ('domain_authorizations', 'dns_txt_verifications', 'domains', 'users', 'integrations'):
            with self.subTest(conserva=tabla):
                self.assertGreater(self.contar(tabla), 0)
        self.assertEqual(postgres("SELECT status || ',' || (service_ended_at IS NOT NULL) FROM organizations "
                                  "WHERE id = '%s';" % ORG), 'cancelled,true')
        self.assertEqual(postgres("SELECT status FROM domains WHERE id = '%s';" % DOM), 'paused')
        self.assertEqual(postgres("SELECT string_agg(is_active::text, ',') FROM users WHERE organization_id = '%s';"
                                  % ORG), 'false,false')
        self.assertEqual(postgres("SELECT revoked_at IS NOT NULL FROM api_keys WHERE organization_id = '%s';" % ORG),
                         't')
        evento = postgres("SELECT action || ' ' || details::text FROM audit_log WHERE organization_id = '%s' "
                          "ORDER BY chain_seq DESC LIMIT 1;" % ORG)
        self.assertTrue(evento.startswith('service.ended '), evento)
        for texto in ('"reason": "Cierre del curso"', '"findings": 2', '"assets": 2', '"domain_scores": 1',
                      '"previous_status": "active"', '"confirmation_to": 1'):
            self.assertIn(texto, evento)
        self.assertNotIn('rc258.invalid', evento)   # conteos, sin datos
        self.assertEqual(scalar("SELECT count(*) FROM findings WHERE organization_id = '%s';" % ACME, user='postgres'),
                         acme_antes)
        # Otra vez no rompe nada: ya no queda qué borrar
        r = comando('cirdan.fin_servicio', 'terminar', ORG, '--motivo', 'Otra vez', '--sin-correo')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('0 filas borradas', r.stdout)

    def test_2_motivo_y_empresa_invalidos_no_cambian_nada(self):
        for args in (('terminar', ORG, '--motivo', 'x'), ('terminar', 'no-es-uuid', '--motivo', 'Motivo'),
                     ('terminar', 'e1400000-0000-4000-8000-999999999999', '--motivo', 'Motivo')):
            with self.subTest(args=args):
                self.assertEqual(comando('cirdan.fin_servicio', *args, '--sin-correo').returncode, 2)
        self.assertEqual(self.contar('findings'), 2)
        self.assertEqual(postgres("SELECT status FROM organizations WHERE id = '%s';" % ORG), 'active')

    def test_3_cancelar_una_cuenta_borra_huella_y_totp_y_al_vencer_el_plazo_la_anonimiza(self):
        r = comando('cirdan.fin_servicio', 'cancelar-usuario', ANA, '--organizacion', ORG, '--motivo',
                    'La persona pidió cancelar su cuenta', con_contrasena=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        fila = postgres("SELECT password_hash || '|' || (totp_secret_enc IS NULL) || '|' || (mfa_enabled_at IS NULL) "
                        "|| '|' || is_active || '|' || (cancelled_at IS NOT NULL) FROM users WHERE id = '%s';" % ANA)
        self.assertEqual(fila, '%s|true|true|false|true' % HASH_DE_RELLENO)
        self.assertTrue(postgres("SELECT action FROM audit_log WHERE organization_id = '%s' ORDER BY chain_seq DESC "
                                 "LIMIT 1;" % ORG).startswith('user.cancelled'))
        self.assertEqual(comando('cirdan.fin_servicio', 'cancelar-usuario', ANA, '--organizacion', ORG, '--motivo',
                                 'Otra vez', con_contrasena=False).returncode, 2)
        # Antes del plazo el nombre y el correo siguen; al vencer, el job de retención los anonimiza
        self.assertEqual(comando('cirdan.retencion', '--una-vez', '--organizacion', ORG).returncode, 0)
        self.assertEqual(postgres("SELECT email FROM users WHERE id = '%s';" % ANA), 'ana@rc258.invalid')
        postgres("UPDATE users SET cancelled_at = now() - interval '13 months' WHERE id = '%s';" % ANA)
        self.assertEqual(comando('cirdan.retencion', '--una-vez', '--organizacion', ORG).returncode, 0)
        self.assertEqual(postgres("SELECT full_name || '|' || email FROM users WHERE id = '%s';" % ANA),
                         'Cuenta cancelada|cancelada-%s@cancelada.invalid' % ANA)
        # La otra cuenta no se toca
        self.assertEqual(postgres("SELECT email FROM users WHERE id = '%s';" % ADMIN), 'admin@rc258.invalid')


if __name__ == '__main__':
    unittest.main()

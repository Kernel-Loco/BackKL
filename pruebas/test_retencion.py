"""Retención de 12 meses (#139, RC-257) contra la base del compose desechable.

    python -m unittest -v pruebas/test_retencion.py      (con el compose desechable y CIRDAN_RETENTION_PASSWORD en .env)

Siembra en acme-demo.mx filas de 13 y de 11 meses, corre el job (`python -m cirdan.retencion --una-vez`) dentro del
contenedor de la API con el rol cirdan_retention y revisa que se borren las de 13, queden las de 11 y un hallazgo
abierto de 13 meses, que cirdan_app siga sin poder borrar y que el rol de retención no vea otra empresa.
"""
import os
import subprocess
import unittest
from pathlib import Path

from pruebas.pila import exigir_desechable
from pruebas.test_aislamiento import psql, scalar

RAIZ = Path(__file__).resolve().parents[1]
ACME = '20000000-0000-4000-8000-000000000001'
BETA = '20000000-0000-4000-8000-000000000002'
DOMINIO = '40000000-0000-4000-8000-000000000001'   # acme-demo.mx
API = os.environ.get('CIRDAN_TEST_API_CONTAINER', 'cirdan-api')


def uid(n):
    return 'e1390000-0000-4000-8000-%012d' % n


S13, S11, R13, R11 = uid(1), uid(2), uid(3), uid(4)
A13, A11, AF = uid(5), uid(6), uid(7)
F13R, F13O, F11R = uid(8), uid(9), uid(10)
DS13, DS11, C13, C11 = uid(11), uid(12), uid(13), uid(14)
INTEG, AL13, AL11, DL13 = uid(15), uid(16), uid(17), uid(18)
TODOS = {'deliveries': [DL13], 'alerts': [AL13, AL11], 'score_contributions': [C13, C11],
         'domain_scores': [DS13, DS11], 'breach_exposures': [F13R], 'findings': [F13R, F13O, F11R],
         'assets': [A13, A11, AF], 'scan_source_runs': [R13, R11], 'scans': [S13, S11], 'integrations': [INTEG]}
BORRADOS = {DL13, AL13, C13, DS13, F13R, A13, R13, S13}

SEMBRAR = """
BEGIN;
-- Un escaneo de hace 13 meses no tiene carta vigente en esa fecha: la siembra salta los triggers, el job no.
SET LOCAL session_replication_role = replica;
INSERT INTO scans (id, organization_id, domain_id, authorization_id, txt_verification_id, trigger_type, status,
                   queued_at, finished_at)
SELECT x.id, s.organization_id, s.domain_id, s.authorization_id, s.txt_verification_id, 'scheduled', 'completed',
       now() - x.edad, now() - x.edad
  FROM (VALUES ('{S13}'::uuid, interval '13 months'), ('{S11}'::uuid, interval '11 months')) x(id, edad),
       LATERAL (SELECT * FROM scans WHERE domain_id = '{D}' ORDER BY queued_at LIMIT 1) s;
INSERT INTO scan_source_runs (id, organization_id, scan_id, source_id, status, finished_at)
SELECT x.id, '{O}', x.scan, (SELECT id FROM data_sources WHERE code = 'dns'), 'succeeded', now()
  FROM (VALUES ('{R13}'::uuid, '{S13}'::uuid), ('{R11}'::uuid, '{S11}'::uuid)) x(id, scan);
INSERT INTO assets (id, organization_id, domain_id, asset_type, value, first_seen_at, last_seen_at)
VALUES ('{A13}', '{O}', '{D}', 'subdomain', 'rc257-13.acme-demo.mx', now() - interval '14 months', now() - interval '13 months'),
       ('{A11}', '{O}', '{D}', 'subdomain', 'rc257-11.acme-demo.mx', now() - interval '12 months', now() - interval '11 months'),
       ('{AF}',  '{O}', '{D}', 'subdomain', 'rc257-f.acme-demo.mx',  now() - interval '14 months', now() - interval '13 months');
INSERT INTO findings (id, organization_id, domain_id, asset_id, rule_id, source_id, fingerprint, severity, status,
                      evidence, detected_at, resolved_at, last_scan_id)
SELECT x.id, '{O}', '{D}', '{AF}',
       (SELECT id FROM scoring_rules WHERE rule_set_id = '90000000-0000-4000-8000-000000000001' AND code = 'breach_exposure'),
       (SELECT id FROM data_sources WHERE code = 'dns'), sha256(convert_to('rc257-' || x.id::text, 'UTF8')), 'high',
       x.estado, '{{"title": "Hallazgo de retención de prueba"}}', now() - interval '14 months', x.resuelto, '{S13}'
  FROM (VALUES ('{F13R}'::uuid, 'resolved', now() - interval '13 months'),
               ('{F13O}'::uuid, 'open', NULL::timestamptz),
               ('{F11R}'::uuid, 'resolved', now() - interval '11 months')) x(id, estado, resuelto);
INSERT INTO breach_exposures (finding_id, organization_id, breach_name, data_classes)
VALUES ('{F13R}', '{O}', 'RC257-Prueba', ARRAY['Email addresses']);
INSERT INTO domain_scores (id, organization_id, domain_id, scan_id, rule_set_id, score, category_scores, reason, computed_at)
SELECT x.id, '{O}', '{D}', x.scan, '90000000-0000-4000-8000-000000000001', 50, '{{}}', 'scan', now() - x.edad
  FROM (VALUES ('{DS13}'::uuid, '{S13}'::uuid, interval '13 months'),
               ('{DS11}'::uuid, '{S11}'::uuid, interval '11 months')) x(id, scan, edad);
INSERT INTO score_contributions (id, organization_id, score_id, finding_id, rule_id, penalty, severity, factors)
SELECT x.id, '{O}', x.score, '{F13O}',
       (SELECT id FROM scoring_rules WHERE rule_set_id = '90000000-0000-4000-8000-000000000001' AND code = 'breach_exposure'),
       5, 'high', '{{}}'
  FROM (VALUES ('{C13}'::uuid, '{DS13}'::uuid), ('{C11}'::uuid, '{DS11}'::uuid)) x(id, score);
INSERT INTO integrations (id, organization_id, kind, name, endpoint)
VALUES ('{INTEG}', '{O}', 'webhook', 'RC-257 prueba', 'example.invalid');
INSERT INTO alerts (id, organization_id, domain_id, event_type, finding_id, severity, payload, detected_at)
VALUES ('{AL13}', '{O}', '{D}', 'finding.created', '{F13O}', 'high', '{{}}', now() - interval '13 months'),
       ('{AL11}', '{O}', '{D}', 'finding.created', '{F13O}', 'high', '{{}}', now() - interval '11 months');
INSERT INTO deliveries (id, organization_id, integration_id, alert_id, status, message_id, detected_at)
VALUES ('{DL13}', '{O}', '{INTEG}', '{AL13}', 'delivered', 'rc257-prueba-{DL13}', now() - interval '13 months');
COMMIT;
"""


def contrasena():
    """La de cirdan_retention: del entorno o del .env que el CI arma con contraseñas al azar."""
    if os.environ.get('CIRDAN_RETENTION_PASSWORD'):
        return os.environ['CIRDAN_RETENTION_PASSWORD']
    for linea in (RAIZ / '.env').read_text(encoding='utf-8').splitlines():
        if linea.startswith('CIRDAN_RETENTION_PASSWORD='):
            return linea.split('=', 1)[1].strip()
    return ''


def correr_retencion():
    exigir_desechable()
    return subprocess.run(['docker', 'exec', '-e', 'CIRDAN_RETENTION_PASSWORD=' + contrasena(), API,
                           'python', '-m', 'cirdan.retencion', '--una-vez', '--organizacion', ACME],
                          capture_output=True, text=True, encoding='utf-8', timeout=120)


def existen(tabla, ids):
    llave = 'finding_id' if tabla == 'breach_exposures' else 'id'
    lista = ','.join("'%s'" % i for i in ids)
    salida = scalar('SELECT coalesce(string_agg(%s::text, \',\' ORDER BY %s), \'\') FROM %s WHERE %s IN (%s);'
                    % (llave, llave, tabla, llave, lista), user='postgres')
    return set(filter(None, salida.split(',')))


class Retencion(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not contrasena():
            raise unittest.SkipTest('sin CIRDAN_RETENTION_PASSWORD (el CI la pone en .env)')

    def setUp(self):
        self.seq = int(scalar("SELECT coalesce(max(chain_seq), 0) FROM audit_log WHERE organization_id = '%s';" % ACME,
                              user='postgres'))
        borrar = ['DELETE FROM %s WHERE %s IN (%s);' % (t, 'finding_id' if t == 'breach_exposures' else 'id',
                                                       ','.join("'%s'" % i for i in ids))
                  for t, ids in TODOS.items()]
        self.addCleanup(self._limpiar, 'BEGIN; SET LOCAL session_replication_role = replica; ' + ' '.join(borrar)
                        + " DELETE FROM audit_log WHERE organization_id = '%s' AND chain_seq > %d; COMMIT;"
                        % (ACME, self.seq))
        ok, _, err = psql(SEMBRAR.format(O=ACME, D=DOMINIO, **{k: v for k, v in globals().items()
                                                              if k.isupper() and isinstance(v, str)}), user='postgres')
        self.assertTrue(ok, err)

    def _limpiar(self, sql):
        ok, _, err = psql(sql, user='postgres')
        if not ok:
            raise AssertionError('quedaron filas de la prueba de retención: %s' % err)

    def test_1_borra_lo_de_13_meses_y_deja_lo_de_11_y_lo_abierto(self):
        r = correr_retencion()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for tabla, ids in TODOS.items():
            with self.subTest(tabla=tabla):
                self.assertEqual(existen(tabla, ids), set(ids) - BORRADOS)
        # El hallazgo abierto de 13 meses sigue, sin el escaneo viejo que ya no existe.
        self.assertEqual(scalar("SELECT status || ',' || coalesce(last_scan_id::text, 'null') FROM findings "
                                "WHERE id = '%s';" % F13O, user='postgres'), 'open,null')

    def test_2_deja_en_la_bitacora_cuantas_filas_borro_por_tabla(self):
        self.assertEqual(correr_retencion().returncode, 0)
        detalles = scalar("SELECT details::text FROM audit_log WHERE organization_id = '%s' AND action = "
                          "'retention.purged' AND chain_seq > %d ORDER BY chain_seq DESC LIMIT 1;" % (ACME, self.seq),
                          user='postgres')
        for tabla in ('deliveries', 'alerts', 'score_contributions', 'domain_scores', 'breach_exposures', 'findings',
                      'assets', 'scan_source_runs', 'scans'):
            self.assertIn('"%s": 1' % tabla, detalles)
        self.assertIn('"reports": 0', detalles)
        self.assertIn('"total": 9', detalles)
        self.assertNotIn('rc257', detalles)   # conteos, sin datos de las filas
        self.assertEqual(scalar("SELECT actor_type FROM audit_log WHERE organization_id = '%s' AND chain_seq > %d "
                                "ORDER BY chain_seq DESC LIMIT 1;" % (ACME, self.seq), user='postgres'), 'system')

    def test_3_cirdan_app_no_borra_y_retencion_no_borra_lo_reciente_ni_ve_otra_empresa(self):
        ok, _, err = psql("DELETE FROM domain_scores WHERE id = '%s';" % DS13, org=ACME)
        self.assertFalse(ok)
        ok, _, err = psql("DELETE FROM domain_scores WHERE id = '%s';" % DS11, user='cirdan_retention', org=ACME)
        self.assertFalse(ok)
        self.assertIn('solo inserción', err)
        self.assertEqual(scalar("SELECT count(*) FROM findings WHERE organization_id = '%s';" % ACME,
                                user='cirdan_retention', org=BETA), '0')
        self.assertEqual(scalar("SELECT rolsuper || ',' || rolbypassrls FROM pg_roles "
                                "WHERE rolname = 'cirdan_retention';", user='postgres'), 'false,false')
        ok, _, _ = psql("DELETE FROM audit_log WHERE organization_id = '%s';" % ACME, user='cirdan_retention', org=ACME)
        self.assertFalse(ok)
        ok, _, _ = psql("SELECT count(*) FROM domain_authorizations;", user='cirdan_retention', org=ACME)
        self.assertFalse(ok)   # no tiene permiso: las cartas y el TXT van en #140


if __name__ == '__main__':
    unittest.main()

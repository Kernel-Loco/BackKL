"""API de la integración con Teams (#65, RC-114) contra el compose desechable.

    python -m unittest -v pruebas/test_integracion_teams.py      (con el compose desechable)

Solo el Admin conecta el canal. La URL del flujo nunca vuelve en una respuesta ni queda en claro en la base: en
`endpoint` solo va el host y la bitácora solo lleva el host. Una URL que no es de Workflows de Microsoft es 422.
"""
import unittest

from pruebas import sesion
from pruebas.test_aislamiento import ACME, BETA, psql, scalar

ALEX, MAYA, DANA = 'alex.morgan@acme-demo.mx', 'maya.reed@acme-demo.mx', 'dana.cruz@beta-corp.mx'
RUTA = '/api/v1/integrations/teams'
FIRMA = 'firma-de-prueba-rc114'   # sin forma de token (regla lowtide-token-falso-fuera-de-fixtures)
URL = ('https://prod-12.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?api-version=1&sig=' + FIRMA)
HOST = 'prod-12.westus.logic.azure.com'


def postgres(sql):
    ok, salida, err = psql(sql, user='postgres')
    if not ok:
        raise AssertionError(err)
    return salida


class IntegracionTeams(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sesion.reset()
        cls.alex = sesion.login(ALEX)
        cls.dana = sesion.login(DANA)

    def setUp(self):
        seqs = {org: int(scalar("SELECT coalesce(max(chain_seq), 0) FROM audit_log WHERE organization_id = '%s';" % org,
                                user='postgres')) for org in (ACME, BETA)}
        self.addCleanup(postgres, "BEGIN; SET LOCAL session_replication_role = replica; "
                        "DELETE FROM integrations WHERE organization_id IN ('%s', '%s') AND config->>'formato' = 'teams'; "
                        "DELETE FROM audit_log WHERE (organization_id = '%s' AND chain_seq > %d) "
                        "OR (organization_id = '%s' AND chain_seq > %d); COMMIT;"
                        % (ACME, BETA, ACME, seqs[ACME], BETA, seqs[BETA]))

    def test_1_el_admin_conecta_el_canal_y_la_url_nunca_vuelve(self):
        self.assertEqual(self.alex.get(RUTA), (200, {'configured': False, 'enabled': False, 'host': None,
                                                     'last_delivery': None}))
        code, body = self.alex.request('PUT', RUTA, {'url': URL})
        self.assertEqual(code, 200, body)
        self.assertEqual((body['configured'], body['enabled'], body['host']), (True, True, HOST))
        self.assertNotIn(FIRMA, str(body))
        self.assertNotIn(FIRMA, str(self.alex.get(RUTA)[1]))
        fila = postgres("SELECT endpoint || '|' || encode(secret_enc, 'escape') || '|' || (config->>'formato') "
                        "FROM integrations WHERE organization_id = '%s' AND config->>'formato' = 'teams';" % ACME)
        self.assertTrue(fila.startswith(HOST + '|'))
        self.assertTrue(fila.endswith('|teams'))
        self.assertNotIn(FIRMA, fila)                     # cifrada: la firma no está en claro
        evento = postgres("SELECT action || ' ' || details::text FROM audit_log WHERE organization_id = '%s' "
                          "ORDER BY chain_seq DESC LIMIT 1;" % ACME)
        self.assertTrue(evento.startswith('integration.teams_set '))
        self.assertIn(HOST, evento)
        self.assertNotIn(FIRMA, evento)
        # Poner otra URL reemplaza la misma integración
        self.assertEqual(self.alex.request('PUT', RUTA, {'url': URL.replace('prod-12', 'prod-13'), 'enabled': False})
                         [1]['enabled'], False)
        self.assertEqual(postgres("SELECT count(*) FROM integrations WHERE organization_id = '%s' AND config->>'formato' = 'teams';" % ACME), '1')
        # Cada empresa ve la suya
        self.assertFalse(self.dana.get(RUTA)[1]['configured'])

    def test_2_url_invalida_es_422_y_solo_el_admin_entra(self):
        for url in ('http://prod-12.westus.logic.azure.com/x?sig=1', 'https://example.com/x?sig=1',
                    URL.replace('&sig=' + FIRMA, ''), 'https://169.254.169.254/x?sig=1', None):
            with self.subTest(url=url):
                code, body = self.alex.request('PUT', RUTA, {'url': url})
                self.assertEqual(code, 422, body)
        self.assertEqual(self.alex.request('PUT', RUTA, {'url': URL, 'canal': 'x'})[0], 422)
        maya = sesion.login(MAYA)
        for metodo, cuerpo in (('GET', None), ('PUT', {'url': URL}), ('DELETE', None)):
            with self.subTest(metodo=metodo):
                self.assertEqual(maya.request(metodo, RUTA, cuerpo)[0], 403)
        self.assertEqual(maya.post(RUTA + '/test', {})[0], 403)

    def test_3_desconectar_borra_la_url(self):
        self.assertEqual(self.alex.request('DELETE', RUTA)[0], 404)
        self.assertEqual(self.alex.request('PUT', RUTA, {'url': URL})[0], 200)
        self.assertEqual(self.alex.request('DELETE', RUTA)[0], 204)
        self.assertEqual(postgres("SELECT enabled || ',' || (secret_enc IS NULL) FROM integrations "
                                  "WHERE organization_id = '%s' AND config->>'formato' = 'teams';" % ACME), 'false,true')
        self.assertEqual(self.alex.post(RUTA + '/test', {})[0], 404)


if __name__ == '__main__':
    unittest.main()

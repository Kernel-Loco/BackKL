"""Inventario de activos de la organización (#113, RC-231) contra la API local (biblioteca estándar).

    python -m unittest -v pruebas/test_inventario_activos.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Hecho cuando de RC-231: GET /api/v1/assets da los activos de la empresa con dominio, tipo, valor, activo padre y fechas,
con filtros por dominio, tipo y texto y con paginación, y los lee cirdan_app con RLS. Una empresa no ve los activos de
otra, los filtros y la paginación dan lo esperado y el CSV escapa las fórmulas.

Lo esperado sale de la base (como postgres), no de números fijos, así una semilla nueva no rompe la prueba. Los activos
con fórmula entran en acme-demo.mx con ids 70000000-0000-4000-8000-000000231xxx y se borran al final. Las llaves se
llaman CIRDAN_FAKE_... y las limpia borrar_llaves() de test_llaves_api.py.
"""
import csv
import io
import unittest
from urllib.parse import quote

from pruebas import sesion
from pruebas.test_aislamiento import ACME, BETA, psql, scalar
from pruebas.test_bitacora_descargas import descargar, ultimo_seq
from pruebas.test_llaves_api import borrar_llaves, get, poner_plan

ALEX = 'alex.morgan@acme-demo.mx'     # admin de Acme
DANA = 'dana.cruz@beta-corp.mx'       # admin de Beta
CAMPOS = {'id', 'domain', 'type', 'value', 'ip', 'parent', 'parent_type', 'attributes', 'first_seen_at', 'last_seen_at'}
ORDEN = ("array_position(ARRAY['domain','subdomain','certificate','ip','service','api_doc','email'], a.asset_type)")
FORMULAS = ('=HYPERLINK("http://x.test")', '+1+1', '-2+3', '@SUM(A1)', 'ok;=1+1')
PREFIJO_ID = '70000000-0000-4000-8000-000000231'
CARTA_VIGENTE = ('EXISTS (SELECT 1 FROM domain_authorizations x WHERE x.domain_id = d.id AND x.revoked_at IS NULL '
                 'AND current_date BETWEEN x.valid_from AND x.valid_until)')


def ids(sql):
    """Ids de activos (como texto) de una consulta como postgres, en el orden de la API."""
    ok, salida, err = psql(sql, user='postgres')
    assert ok, err
    return [x for x in salida.splitlines() if x]


def esperados(where='true'):
    return ids("SELECT a.id FROM assets a JOIN domains d ON d.id = a.domain_id WHERE %s "
               "ORDER BY d.fqdn, %s, a.value, a.id;" % (where, ORDEN))


def todo(cliente, filtros=''):
    """Todas las páginas de GET /assets con ese filtro, de 200 en 200."""
    items, offset = [], 0
    while True:
        code, body = cliente.get('/api/v1/assets?limit=200&offset=%d%s' % (offset, filtros))
        assert code == 200, body
        items += body['items']
        offset += 200
        if offset >= body['total']:
            return items, body['total']


def filas_csv(texto):
    return list(csv.DictReader(io.StringIO(texto.lstrip('﻿'), newline='')))


class InventarioActivos(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sesion.reset()
        borrar_llaves()
        cls.alex = sesion.login(ALEX)
        cls.beta = sesion.login(DANA)
        cls.acme_demo = scalar("SELECT id FROM domains WHERE fqdn = 'acme-demo.mx';", user='postgres')

    def tearDown(self):
        poner_plan(ACME, 'starter')
        borrar_llaves()

    def test_1_cada_empresa_ve_solo_sus_activos(self):
        for cliente, org in ((self.alex, ACME), (self.beta, BETA)):
            items, total = todo(cliente)
            self.assertEqual([i['id'] for i in items], esperados("a.organization_id = '%s'" % org), org)
            self.assertEqual(total, len(items))
            self.assertTrue(items, org)
            self.assertEqual(set(items[0]), CAMPOS)
        # Beta no ve un dominio de Acme ni por filtro ni por texto: total 0, como GET /scans.
        code, body = self.beta.get('/api/v1/assets?domain=acme-demo.mx')
        self.assertEqual((code, body['items'], body['total']), (200, [], 0))
        acme = set(esperados("a.organization_id = '%s'" % ACME))
        self.assertFalse(acme & {i['id'] for i in todo(self.beta, '&q=acme')[0]})
        # Sin sesión, 401.
        self.assertEqual(sesion.Client().get('/api/v1/assets')[0], 401)

    def test_2_filtros_por_dominio_tipo_y_texto(self):
        org = "a.organization_id = '%s'" % ACME
        casos = (
            ('&domain=acme-demo.mx', org + " AND d.fqdn = 'acme-demo.mx'"),
            ('&domain=ACME-Demo.MX', org + " AND d.fqdn = 'acme-demo.mx'"),   # fqdn es citext
            ('&type=subdomain', org + " AND a.asset_type = 'subdomain'"),
            ('&q=ACME', org + " AND strpos(lower(a.value), 'acme') > 0"),
            ('&domain=acme-demo.mx&type=ip', org + " AND d.fqdn = 'acme-demo.mx' AND a.asset_type = 'ip'"),
            ('&q=%25', org + " AND strpos(a.value, '%') > 0"),                # % no es comodín
            ('&q=_', org + " AND strpos(a.value, '_') > 0"),
            ('&domain=no-existe.mx', 'false'),
        )
        for filtro, where in casos:
            items, total = todo(self.alex, filtro)
            self.assertEqual([i['id'] for i in items], esperados(where), filtro)
            self.assertEqual(total, len(items), filtro)
        self.assertTrue(todo(self.alex, '&type=subdomain')[0])
        self.assertTrue(all(i['type'] == 'subdomain' for i in todo(self.alex, '&type=subdomain')[0]))
        # El padre sale con su valor y su tipo.
        hijos = [i for i in todo(self.alex)[0] if i['parent']]
        self.assertTrue(hijos)
        self.assertTrue(all(i['parent_type'] for i in hijos))
        for malo in ('type=otro', 'domain=', 'q=', 'q=' + 'x' * 201, 'limit=0', 'limit=201', 'offset=-1',
                     'offset=1000001', 'formato=xml'):
            self.assertEqual(self.alex.get('/api/v1/assets?' + malo)[0], 422, malo)

    def test_3_paginacion(self):
        todos = esperados("a.organization_id = '%s'" % ACME)
        self.assertGreater(len(todos), 5)
        paginas = []
        for offset in range(0, len(todos) + 3, 3):
            code, body = self.alex.get('/api/v1/assets?limit=3&offset=%d' % offset)
            self.assertEqual(code, 200, body)
            self.assertEqual((body['total'], body['limit'], body['offset']), (len(todos), 3, offset))
            self.assertLessEqual(len(body['items']), 3)
            paginas += [i['id'] for i in body['items']]
        self.assertEqual(paginas, todos)
        code, body = self.alex.get('/api/v1/assets')
        self.assertEqual((body['limit'], body['offset'], len(body['items'])), (50, 0, min(50, len(todos))))

    def test_4_csv_escapa_formulas_y_deja_bitacora(self):
        valores = ',\n'.join(
            "('%s%03d', '%s', '%s', NULL, 'subdomain', $v$%s$v$, NULL, '{\"banner\": \"=cmd|calc\"}', now(), now())"
            % (PREFIJO_ID, n, ACME, self.acme_demo, v) for n, v in enumerate(FORMULAS))
        self.addCleanup(psql, "DELETE FROM assets WHERE id::text LIKE '%s%%';" % PREFIJO_ID, user='postgres')
        ok, _, err = psql('INSERT INTO assets (id, organization_id, domain_id, parent_asset_id, asset_type, value, '
                          'ip_address, attributes, first_seen_at, last_seen_at) VALUES %s;' % valores, user='postgres')
        self.assertTrue(ok, err)
        antes = ultimo_seq(ACME)
        code, texto = descargar('/api/v1/assets?formato=csv&domain=acme-demo.mx', self.alex)
        self.assertEqual(code, 200, texto)
        self.assertTrue(texto.startswith('﻿'))
        filas = filas_csv(texto)
        self.assertEqual([f['activo_id'] for f in filas], esperados("d.fqdn = 'acme-demo.mx'"))
        nuevas = {f['activo_id']: f for f in filas if f['activo_id'].startswith(PREFIJO_ID)}
        self.assertEqual(len(nuevas), len(FORMULAS))
        for n, v in enumerate(FORMULAS):
            celda = nuevas['%s%03d' % (PREFIJO_ID, n)]['valor']
            self.assertFalse(celda[:1] in '=+-@', celda)
            self.assertNotIn(';=', celda)
            self.assertIn(v.lstrip('=+-@').split(';')[0], celda)
        self.assertIn('=cmd|calc', nuevas['%s000' % PREFIJO_ID]['atributos'])  # JSON en una celda, empieza con {
        # Deja un report.downloaded con kind 'assets' y el dominio de la base.
        ok, salida, err = psql("SELECT entity_type, entity_id, details->>'kind', details->>'domain', details->>'rows' "
                               "FROM audit_log WHERE organization_id = '%s' AND chain_seq > %d "
                               "AND action = 'report.downloaded';" % (ACME, antes), user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual([x.split('|') for x in salida.splitlines()],
                         [['domain', self.acme_demo, 'assets', 'acme-demo.mx', str(len(filas))]])

    def test_5_csv_de_la_empresa_solo_con_carta_vigente(self):
        antes = ultimo_seq(ACME)
        code, texto = descargar('/api/v1/assets?formato=csv', self.alex)
        self.assertEqual(code, 200, texto)
        filas = filas_csv(texto)
        self.assertEqual([f['activo_id'] for f in filas],
                         esperados("a.organization_id = '%s' AND %s" % (ACME, CARTA_VIGENTE)))
        self.assertLess(len(filas), len(esperados("a.organization_id = '%s'" % ACME)), 'la semilla trae uno sin carta')
        ok, salida, err = psql("SELECT entity_type, entity_id, details::text FROM audit_log WHERE organization_id = '%s' "
                               "AND chain_seq > %d AND action = 'report.downloaded';" % (ACME, antes), user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual(salida.splitlines(), ['organization|%s|{"kind": "assets", "rows": %d, "domain": null, '
                                               '"format": "csv"}' % (ACME, len(filas))])
        # Un dominio de la empresa sin carta vigente: 403. Uno de otra empresa o que no existe: 404. Sin evento.
        sin_carta = scalar("SELECT d.fqdn FROM domains d WHERE d.organization_id = '%s' AND NOT %s ORDER BY 1 LIMIT 1;"
                           % (ACME, CARTA_VIGENTE), user='postgres')
        antes = ultimo_seq(ACME)
        self.assertEqual(descargar('/api/v1/assets?formato=csv&domain=' + quote(sin_carta), self.alex)[0], 403)
        self.assertEqual(descargar('/api/v1/assets?formato=csv&domain=beta-corp.mx', self.alex)[0], 404)
        self.assertEqual(descargar('/api/v1/assets?formato=csv&domain=no-existe.mx', self.alex)[0], 404)
        self.assertEqual(ultimo_seq(ACME), antes)
        # Beta no recibe filas de Acme.
        code, texto = descargar('/api/v1/assets?formato=csv', self.beta)
        self.assertEqual(code, 200, texto)
        self.assertFalse({f['dominio'] for f in filas_csv(texto)} & {f['dominio'] for f in filas})

    def test_6_llave_de_un_dominio_solo_ve_el_suyo(self):
        poner_plan(ACME, 'business')
        code, llave = self.alex.post('/api/v1/api-keys', {'own_use': True, 'name': 'CIRDAN_FAKE_rc231',
                                                         'domain': 'acme-tienda.mx'})
        self.assertEqual(code, 201, llave)
        code, body = get(llave['key'], '/api/v1/assets?limit=200')
        self.assertEqual(code, 200, body)
        self.assertEqual([i['id'] for i in body['items']], esperados("d.fqdn = 'acme-tienda.mx'"))
        self.assertEqual(get(llave['key'], '/api/v1/assets?domain=acme-demo.mx')[1]['total'], 0)
        code, texto = descargar('/api/v1/assets?formato=csv', llave=llave['key'])
        self.assertEqual(code, 200, texto)
        self.assertEqual({f['dominio'] for f in filas_csv(texto)} - {'acme-tienda.mx'}, set())
        self.assertEqual(descargar('/api/v1/assets?formato=csv&domain=acme-demo.mx', llave=llave['key'])[0], 404)


if __name__ == '__main__':
    unittest.main()

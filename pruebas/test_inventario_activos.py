"""Inventario de activos de la organización (#113, RC-231) contra la API local (biblioteca estándar).

    python -m unittest -v pruebas/test_inventario_activos.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Hecho cuando de RC-231: GET /api/v1/assets da los activos de la empresa con dominio, tipo, valor, activo padre y fechas,
con filtros por dominio, tipo y texto y con paginación, y los lee cirdan_app con RLS. Una empresa no ve los activos de
otra, los filtros y la paginación dan lo esperado y el CSV escapa las fórmulas.

Lo esperado sale de la base (como postgres), no de números fijos, así una semilla nueva no rompe la prueba. Los activos
con fórmula entran en acme-demo.mx con ids 70000000-0000-4000-8000-000000231xxx y se borran al final. Las cartas de la
semilla vencen el 2026-12-31, así que acme-demo.mx, acme-tienda.mx y beta-corp.mx suman una carta propia que vence en 30
días (ids 41000000-0000-4000-8000-000000231xxx), también borrada al final. Las llaves se llaman CIRDAN_FAKE_... y las
limpia borrar_llaves() de test_llaves_api.py.
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
ORDEN = ("array_position(ARRAY['domain','subdomain','certificate','ip','service','api_doc','email','profile'], a.asset_type)")
FORMULAS = ('=HYPERLINK("http://x.test")', '+1+1', '-2+3', '@SUM(A1)', 'ok;=1+1')
PREFIJO_ID = '70000000-0000-4000-8000-000000231'
PREFIJO_TOPE = '70000000-0000-4000-8231-'   # los activos de la prueba del tope de 50 000
PREFIJO_CARTA = '41000000-0000-4000-8000-000000231'
CON_CARTA_PROPIA = ('acme-demo.mx', 'acme-tienda.mx', 'beta-corp.mx')
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


def insertar(filas):
    """Activos de prueba [(n, fqdn, tipo, valor)] con id PREFIJO_ID + n, como postgres, con un banner con fórmula."""
    valores = ', '.join("('%s%03d', '%s', '%s', $v$%s$v$)" % (PREFIJO_ID, n, fqdn, tipo, valor)
                        for n, fqdn, tipo, valor in filas)
    ok, _, err = psql('INSERT INTO assets (id, organization_id, domain_id, asset_type, value, attributes, first_seen_at, '
                      'last_seen_at) SELECT v.id::uuid, d.organization_id, d.id, v.tipo, v.valor, '
                      '\'{"banner": "=cmd|calc"}\', now(), now() FROM (VALUES %s) AS v(id, fqdn, tipo, valor) '
                      'JOIN domains d ON d.fqdn = v.fqdn;' % valores, user='postgres')
    assert ok, err


def borrar_insertados(prefijo=PREFIJO_ID):
    ok, _, err = psql("DELETE FROM assets WHERE id::text LIKE '%s%%';" % prefijo, user='postgres')
    assert ok, err


def poner_cartas():
    """Una carta vigente por 30 días en cada dominio de CON_CARTA_PROPIA, copiada de la primera carta del dominio."""
    hoy = "(now() AT TIME ZONE 'America/Mexico_City')::date"
    sql = 'BEGIN;'
    for n, fqdn in enumerate(CON_CARTA_PROPIA):
        sql += ("INSERT INTO domain_authorizations (id, organization_id, domain_id, signer_name, signer_title, "
                "signer_email, signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, "
                "template_version, activities) "
                "SELECT '%s%03d', x.organization_id, x.domain_id, 'Firma RC-231', 'Prueba', x.signer_email, "
                "x.signed_document_key || '.rc231-%d', x.signed_document_sha256, %s - 1, %s + 30, x.accepted_by, "
                "x.template_version, x.activities "
                "FROM domain_authorizations x JOIN domains d ON d.id = x.domain_id WHERE d.fqdn = '%s' "
                "ORDER BY x.created_at, x.id LIMIT 1;" % (PREFIJO_CARTA, n, n, hoy, hoy, fqdn))
    ok, _, err = psql(sql + 'COMMIT;', user='postgres')
    assert ok, err


def borrar_cartas():
    # domain_authorizations solo acepta UPDATE de revoked_at: el guardia se apaga en esta transacción.
    ok, _, err = psql("BEGIN; SET LOCAL session_replication_role = replica; DELETE FROM domain_authorizations "
                      "WHERE id::text LIKE '%s%%'; COMMIT;" % PREFIJO_CARTA, user='postgres')
    assert ok, err


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
        # La semilla solo trae activos en acme-demo.mx y beta-corp.mx: uno en un dominio sin carta vigente
        # (old-example.net) y tres en otro con carta (acme-tienda.mx), así filtros, páginas y CSV cruzan dominios.
        borrar_insertados()  # los de una corrida cortada
        borrar_insertados(PREFIJO_TOPE)
        borrar_cartas()
        # Si un assert de aquí falla, unittest no llama a tearDownClass: la limpieza va registrada antes de insertar.
        cls.addClassCleanup(borrar_insertados)
        cls.addClassCleanup(borrar_cartas)
        poner_cartas()
        assert scalar("SELECT count(*) FROM domain_authorizations WHERE id::text LIKE '%s%%';" % PREFIJO_CARTA,
                      user='postgres') == str(len(CON_CARTA_PROPIA))
        insertar([(900, 'old-example.net', 'subdomain', 'www.old-example.net'),
                  (901, 'acme-tienda.mx', 'subdomain', 'shop.acme-tienda.mx'),
                  (902, 'acme-tienda.mx', 'ip', '192.0.2.31'),
                  (903, 'acme-tienda.mx', 'subdomain', '_dmarc.acme-tienda.mx')])
        assert scalar("SELECT count(*) FROM assets WHERE id::text LIKE '%s9%%';" % PREFIJO_ID, user='postgres') == '4'

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
                     'offset=1000001', 'formato=xml', 'q=a%00b', 'domain=a%00', 'formato=csv&q=%00'):
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
        self.addCleanup(borrar_insertados, PREFIJO_ID + '0')  # los 0xx de esta prueba, no los 9xx de la clase
        insertar([(n, 'acme-demo.mx', 'subdomain', v) for n, v in enumerate(FORMULAS)])
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
        self.assertNotIn('old-example.net', {f['dominio'] for f in filas})   # su activo 900 no sale: no tiene carta
        self.assertEqual({f['dominio'] for f in filas}, {'acme-demo.mx', 'acme-tienda.mx'})
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
        self.assertEqual({f['dominio'] for f in filas_csv(texto)}, {'beta-corp.mx'})

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
        self.assertEqual([f['activo_id'] for f in filas_csv(texto)], esperados("d.fqdn = 'acme-tienda.mx'"))
        self.assertEqual(len(filas_csv(texto)), 3)
        # Sin ?domain, la bitácora deja el dominio de la llave, no la empresa.
        tienda = scalar("SELECT id FROM domains WHERE fqdn = 'acme-tienda.mx';", user='postgres')
        ok, salida, err = psql("SELECT entity_type, entity_id, details->>'domain', details->>'rows' FROM audit_log "
                               "WHERE organization_id = '%s' AND action = 'report.downloaded' AND details->>'kind' = 'assets' "
                               "ORDER BY chain_seq DESC LIMIT 1;" % ACME, user='postgres')
        self.assertTrue(ok, err)
        self.assertEqual(salida.splitlines(), ['domain|%s|acme-tienda.mx|3' % tienda])
        self.assertEqual(descargar('/api/v1/assets?formato=csv&domain=acme-demo.mx', llave=llave['key'])[0], 404)

    def test_7_csv_con_mas_de_50000_activos_responde_422(self):
        # TOPE_CSV_ACTIVOS de cirdan/api/v1.py. acme-tienda.mx queda con 50 000 activos exactos (sale) y luego con 50 001
        # (422, sin evento en la bitácora). Así se prueba el corte con LIMIT tope + 1 en los dos lados.
        self.addCleanup(borrar_insertados, PREFIJO_TOPE)
        self.addCleanup(borrar_insertados, PREFIJO_ID + '950')
        tope = 50_000
        ya = int(scalar("SELECT count(*) FROM assets a JOIN domains d ON d.id = a.domain_id "
                        "WHERE d.fqdn = 'acme-tienda.mx';", user='postgres'))
        ok, _, err = psql("INSERT INTO assets (id, organization_id, domain_id, asset_type, value, first_seen_at, "
                          "last_seen_at) SELECT ('%s' || lpad(to_hex(n), 12, '0'))::uuid, d.organization_id, d.id, "
                          "'subdomain', 'tope' || n || '.acme-tienda.mx', now(), now() FROM domains d, "
                          "generate_series(1, %d) n WHERE d.fqdn = 'acme-tienda.mx';" % (PREFIJO_TOPE, tope - ya),
                          user='postgres')
        self.assertTrue(ok, err)
        url = '/api/v1/assets?formato=csv&domain=acme-tienda.mx'
        code, texto = descargar(url, self.alex)
        self.assertEqual(code, 200, texto[:200])
        self.assertEqual(len(filas_csv(texto)), tope)
        insertar([(950, 'acme-tienda.mx', 'subdomain', 'uno-mas.acme-tienda.mx')])
        antes = ultimo_seq(ACME)
        code, texto = descargar(url, self.alex)
        self.assertEqual(code, 422, texto[:200])
        self.assertIn('50000', texto)
        self.assertEqual(ultimo_seq(ACME), antes)


if __name__ == '__main__':
    unittest.main()

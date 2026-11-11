"""Pruebas de las llaves de API para integradores (#87, RC-129) contra la API local (biblioteca estándar).

    python -m unittest -v pruebas/test_llaves_api.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Hecho cuando de RC-129: la llave se crea con alcance a un dominio o a toda la empresa y vigencia
máxima de 90 días, se muestra una sola vez y solo se guardan su prefijo y su hash, se puede revocar
y se ve su último uso, y la API la acepta con el mismo aislamiento por empresa. Una llave revocada
o vencida responde 401 y la de otra empresa no ve nada.

Las llaves las genera la API en cada corrida y ninguna queda escrita aquí. Las que estas pruebas
crean llevan un nombre que empieza con CIRDAN_FAKE_ y se borran al terminar cada prueba. Acme es
Starter en la semilla: las pruebas que necesitan que tenga API le ponen Business y lo regresan.
Ninguna pide un escaneo.
"""
import hashlib
import re
import unittest
from concurrent.futures import ThreadPoolExecutor

from pruebas import sesion
from pruebas.sesion import Client
from pruebas.test_aislamiento import ACME, BETA, psql, scalar

JORDAN = 'jordan.tate@acme-demo.mx'   # analista de Acme
MAYA = 'maya.reed@acme-demo.mx'       # gerente de Acme
ALEX = 'alex.morgan@acme-demo.mx'     # admin de Acme (Starter)
DANA = 'dana.cruz@beta-corp.mx'       # admin de Beta (Business)

LLAVES = '/api/v1/api-keys'
FORMATO = re.compile(r'lt_[0-9a-f]{8}_[A-Za-z0-9_-]{43}')
# Con el formato de una llave real, pero inventada: nunca existió en ninguna base.
LLAVE_FALSA = 'lt_00000000_CIRDAN_FAKE_' + 'x' * 31
LLAVE_INVALIDA = 'La llave de API no es válida, venció o fue revocada.'
SIN_SESION = 'Tu sesión terminó. Vuelve a iniciar sesión.'
SIN_PLAN = 'Tu plan no incluye la API. Está disponible en los planes Business y Enterprise.'
HALLAZGO_ACME_DEMO = '80000000-0000-4000-8000-000000000001'
ESCANEO_ACME_DEMO = '60000000-0000-4000-8000-000000000001'
ESCANEO_ACME_TIENDA = '60000000-0000-4000-8000-000000000002'
UUID_CUALQUIERA = '00000000-0000-4000-8000-000000000000'
CAMPOS_LISTA = {'id', 'name', 'key_prefix', 'domain', 'scopes', 'created_by', 'created_at', 'expires_at',
                'last_used_at', 'revoked_at', 'status'}


def postgres(sql):
    ok, out, err = psql(sql, user='postgres')
    if not ok:
        raise AssertionError(err)
    return out


def borrar_llaves():
    postgres("DELETE FROM api_keys WHERE name LIKE 'CIRDAN\\_FAKE\\_%';")


def poner_plan(org, plan):
    postgres("UPDATE organizations SET plan_id = (SELECT id FROM plans WHERE code = '%s') WHERE id = '%s';" % (plan, org))


def con_llave(llave, esquema='Bearer'):
    """(cliente sin cookie, encabezados) para llamar solo con la llave."""
    return Client(), {'Authorization': '%s %s' % (esquema, llave)}


def get(llave, url):
    cliente, encabezados = con_llave(llave)
    return cliente.get(url, headers=encabezados)


def rutas_get_con_dominio():
    """Los GET con {fqdn} que publica la API, tomados de /openapi.json para que una ruta nueva también se pruebe."""
    code, spec = Client().get('/openapi.json')
    assert code == 200, code
    return sorted(ruta for ruta, metodos in spec['paths'].items() if '{fqdn}' in ruta and 'get' in metodos)


class LlavesApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sesion.reset()
        borrar_llaves()
        poner_plan(ACME, 'starter')
        cls.dana = sesion.login(DANA)
        cls.alex = sesion.login(ALEX)
        cls.jordan = sesion.login(JORDAN)
        cls.maya = sesion.login(MAYA)

    def tearDown(self):
        poner_plan(ACME, 'starter')
        postgres("UPDATE organizations SET status = 'active' WHERE id IN ('%s', '%s');" % (ACME, BETA))
        borrar_llaves()

    def crear(self, cliente, nombre='llave', **campos):
        code, body = cliente.post(LLAVES, {'name': 'CIRDAN_FAKE_' + nombre, **campos})
        self.assertEqual(code, 201, body)
        return body

    def estado(self, llave):
        return get(llave, '/api/v1/domains')[0]

    # ------------------------------------------------------------ crear: una sola vez, prefijo y hash

    def test_1_la_llave_se_muestra_una_vez_y_solo_se_guardan_prefijo_y_hash(self):
        body = self.crear(self.dana)
        llave = body['key']
        self.assertRegex(llave, '^%s$' % FORMATO.pattern)
        self.assertEqual(body['key_prefix'], llave[:11])
        self.assertEqual((body['domain'], body['scopes'], body['status']), (None, ['read'], 'active'))
        self.assertEqual(set(body), CAMPOS_LISTA | {'key'})
        guardado = scalar("SELECT key_prefix || ',' || encode(key_hash, 'hex') FROM api_keys WHERE id = '%s';" % body['id'],
                          user='postgres')
        self.assertEqual(guardado, '%s,%s' % (llave[:11], hashlib.sha256(llave.encode()).hexdigest()))
        # La parte secreta no queda en ninguna columna de la llave ni en la bitácora.
        secreto = llave.split('_', 2)[2]
        self.assertEqual(len(secreto), 43)
        for tabla in ('api_keys', 'audit_log'):
            self.assertEqual(scalar("SELECT count(*) FROM %s t WHERE position('%s' in t::text) > 0;" % (tabla, secreto),
                                    user='postgres'), '0', tabla)
        bitacora = scalar("SELECT action || ',' || actor_type || ',' || (details->>'key_prefix') FROM audit_log "
                          "WHERE entity_id = '%s';" % body['id'], user='postgres')
        self.assertEqual(bitacora, 'api_key.created,user,' + llave[:11])
        # La lista ya no la trae, y no hay ruta que la devuelva después.
        code, lista = self.dana.get(LLAVES)
        self.assertEqual((code, lista['total']), (200, 1))
        self.assertEqual(set(lista['items'][0]), CAMPOS_LISTA)
        self.assertNotIn(secreto, str(lista))
        self.assertEqual(self.dana.get(LLAVES + '/' + body['id'])[0], 405)
        otra = self.crear(self.dana, 'otra')
        self.assertNotEqual(otra['key'], llave)

    def test_2_vigencia_maxima_de_90_dias(self):
        for dias in (0, 91, 365, -1):
            code, _ = self.dana.post(LLAVES, {'name': 'CIRDAN_FAKE_vigencia', 'expires_in_days': dias})
            self.assertEqual(code, 422, dias)
        self.assertEqual(scalar("SELECT count(*) FROM api_keys;", user='postgres'), '0')
        por_omision = self.crear(self.dana, 'omision')
        semana = self.crear(self.dana, 'semana', expires_in_days=7)
        dias = scalar("SELECT string_agg(extract(epoch FROM expires_at - created_at)::int / 86400 || '', ',' ORDER BY name) "
                      "FROM api_keys WHERE id IN ('%s', '%s');" % (por_omision['id'], semana['id']), user='postgres')
        self.assertEqual(dias, '90,7')
        # La base tampoco la deja pasar de 90 días, aunque la API se equivocara.
        ok, _, err = psql("BEGIN; INSERT INTO api_keys (organization_id, name, key_prefix, key_hash, scopes, created_by, expires_at) "
                          "VALUES ('%s', 'CIRDAN_FAKE_91', 'lt_ffffffff', '\\x01', '{read}', "
                          "'30000000-0000-4000-8000-000000000004', now() + interval '91 days'); ROLLBACK;" % BETA, org=BETA)
        self.assertFalse(ok)
        self.assertIn('violates check constraint', err)

    def test_3_alcance_a_toda_la_empresa_o_a_un_dominio(self):
        poner_plan(ACME, 'business')
        toda = self.crear(self.alex, 'toda')
        code, body = get(toda['key'], '/api/v1/domains')
        self.assertEqual(code, 200)
        self.assertEqual(sorted(d['fqdn'] for d in body['items']),
                         ['acme-demo.mx', 'acme-portal.mx', 'acme-tienda.mx', 'old-example.net', 'partner-example.com'])

        una = self.crear(self.alex, 'tienda', domain='acme-tienda.mx')
        self.assertEqual(una['domain'], 'acme-tienda.mx')
        llave = una['key']
        code, body = get(llave, '/api/v1/domains')
        self.assertEqual((code, [d['fqdn'] for d in body['items']], body['total']), (200, ['acme-tienda.mx'], 1))
        # Su dominio sí lo lee.
        for ruta in ('/findings', '/score', '/score/history', '/assets'):
            self.assertEqual(get(llave, '/api/v1/domains/acme-tienda.mx' + ruta)[0], 200, ruta)
        self.assertEqual(get(llave, '/api/v1/scans/' + ESCANEO_ACME_TIENDA)[0], 200)
        self.assertEqual(get(llave, '/api/v1/scoring/weights')[0], 200)
        # Los otros dominios de su misma empresa se ven igual que uno que no existe.
        rutas = rutas_get_con_dominio()
        self.assertGreaterEqual(len(rutas), 10)
        for ruta in rutas:
            for dominio in ('acme-demo.mx', 'acme-portal.mx'):
                url = ruta.replace('{fqdn}', dominio) + '?formato=json&desde=%s&hasta=%s' % (UUID_CUALQUIERA, UUID_CUALQUIERA)
                code, _ = get(llave, url)
                self.assertIn(code, (401, 404), url)
        self.assertEqual(get(llave, '/api/v1/findings/%s/explanation' % HALLAZGO_ACME_DEMO)[0], 404)
        self.assertEqual(get(toda['key'], '/api/v1/findings/%s/explanation' % HALLAZGO_ACME_DEMO)[0], 200)
        self.assertEqual(get(llave, '/api/v1/scans/' + ESCANEO_ACME_DEMO)[0], 404)
        self.assertEqual(get(toda['key'], '/api/v1/scans/' + ESCANEO_ACME_DEMO)[0], 200)
        code, body = get(llave, '/api/v1/scans')
        self.assertEqual(code, 200)
        self.assertEqual({s['domain'] for s in body['items']}, {'acme-tienda.mx'})
        self.assertNotIn('domain_id', str(body))
        # Una llave no se crea para el dominio de otra empresa ni para uno que no existe.
        for dominio in ('beta-corp.mx', 'no-existe.example'):
            code, _ = self.alex.post(LLAVES, {'name': 'CIRDAN_FAKE_ajeno', 'domain': dominio})
            self.assertEqual(code, 404, dominio)

    # ------------------------------------------------------------ revocada, vencida y otra empresa

    def test_4_una_llave_revocada_responde_401(self):
        body = self.crear(self.dana)
        self.assertEqual(self.estado(body['key']), 200)
        self.assertEqual(self.dana.request('DELETE', LLAVES + '/' + body['id'])[0], 204)
        code, error = get(body['key'], '/api/v1/domains')
        self.assertEqual((code, error['detail']), (401, LLAVE_INVALIDA))
        for ruta in ('/api/v1/domains/beta-corp.mx/findings', '/api/v1/scans', '/api/v1/scoring/weights'):
            self.assertEqual(get(body['key'], ruta)[0], 401, ruta)
        item = self.dana.get(LLAVES)[1]['items'][0]
        self.assertEqual(item['status'], 'revoked')
        self.assertIsNotNone(item['revoked_at'])
        # Revocar otra vez no cambia la fecha ni repite la bitácora, y nadie la vuelve a activar.
        self.assertEqual(self.dana.request('DELETE', LLAVES + '/' + body['id'])[0], 204)
        self.assertEqual(self.dana.get(LLAVES)[1]['items'][0]['revoked_at'], item['revoked_at'])
        self.assertEqual(scalar("SELECT count(*) FROM audit_log WHERE action = 'api_key.revoked' AND entity_id = '%s';"
                                % body['id'], user='postgres'), '1')
        ok, _, err = psql("UPDATE api_keys SET revoked_at = NULL WHERE id = '%s';" % body['id'], org=BETA)
        self.assertFalse(ok)
        self.assertIn('una llave revocada no se vuelve a activar', err)
        self.assertEqual(self.estado(body['key']), 401)
        for malo in ('no-es-uuid', UUID_CUALQUIERA):
            self.assertEqual(self.dana.request('DELETE', LLAVES + '/' + malo)[0], 404, malo)

    def test_5_una_llave_vencida_responde_401(self):
        body = self.crear(self.dana, expires_in_days=1)
        self.assertEqual(self.estado(body['key']), 200)
        postgres("UPDATE api_keys SET created_at = now() - interval '91 days', expires_at = now() - interval '1 day' "
                 "WHERE id = '%s';" % body['id'])
        code, error = get(body['key'], '/api/v1/domains')
        self.assertEqual((code, error['detail']), (401, LLAVE_INVALIDA))
        self.assertEqual(get(body['key'], '/api/v1/domains/beta-corp.mx/findings')[0], 401)
        self.assertEqual(self.dana.get(LLAVES)[1]['items'][0]['status'], 'expired')
        # La aplicación no puede alargarle la vigencia a una llave que ya existe.
        ok, _, err = psql("UPDATE api_keys SET expires_at = now() + interval '1 day' WHERE id = '%s';" % body['id'], org=BETA)
        self.assertFalse(ok)
        self.assertIn('permission denied', err)

    def test_6_la_llave_de_otra_empresa_no_ve_nada(self):
        llave = self.crear(self.dana)['key']
        code, body = get(llave, '/api/v1/domains')
        self.assertEqual(code, 200)
        self.assertEqual([d['fqdn'] for d in body['items']], ['beta-corp.mx'])
        self.assertEqual(body, self.dana.get('/api/v1/domains')[1], 'la llave ve lo mismo que la sesión de su empresa')
        self.assertEqual(get(llave, '/api/v1/domains/beta-corp.mx/findings')[0], 200)
        for ruta in rutas_get_con_dominio():
            for dominio in ('acme-demo.mx', 'acme-tienda.mx'):
                url = ruta.replace('{fqdn}', dominio) + '?formato=json&desde=%s&hasta=%s' % (UUID_CUALQUIERA, UUID_CUALQUIERA)
                code, _ = get(llave, url)
                self.assertIn(code, (401, 404), url)
        self.assertEqual(get(llave, '/api/v1/findings/%s/explanation' % HALLAZGO_ACME_DEMO)[0], 404)
        self.assertEqual(get(llave, '/api/v1/scans/' + ESCANEO_ACME_DEMO)[0], 404)
        code, body = get(llave, '/api/v1/scans')
        self.assertEqual(code, 200)
        self.assertEqual({s['domain'] for s in body['items']} - {'beta-corp.mx'}, set())
        self.assertNotIn('acme', str(body))
        # El admin de Acme no la ve en su lista ni la puede revocar.
        self.assertEqual(self.alex.get(LLAVES)[1], {'items': [], 'total': 0})
        llave_id = self.dana.get(LLAVES)[1]['items'][0]['id']
        self.assertEqual(self.alex.request('DELETE', LLAVES + '/' + llave_id)[0], 404)
        self.assertEqual(self.estado(llave), 200)

    # ------------------------------------------------------------ último uso

    def test_7_se_ve_el_ultimo_uso(self):
        body = self.crear(self.dana)
        self.assertIsNone(self.dana.get(LLAVES)[1]['items'][0]['last_used_at'])
        self.assertEqual(self.estado(body['key']), 200)
        primero = self.dana.get(LLAVES)[1]['items'][0]['last_used_at']
        self.assertIsNotNone(primero)
        # Dentro del mismo minuto no se vuelve a escribir.
        self.assertEqual(self.estado(body['key']), 200)
        self.assertEqual(self.dana.get(LLAVES)[1]['items'][0]['last_used_at'], primero)
        postgres("UPDATE api_keys SET last_used_at = now() - interval '2 minutes' WHERE id = '%s';" % body['id'])
        viejo = self.dana.get(LLAVES)[1]['items'][0]['last_used_at']
        self.assertEqual(self.estado(body['key']), 200)
        self.assertGreater(self.dana.get(LLAVES)[1]['items'][0]['last_used_at'], viejo)
        # Una llave que no sirve no deja uso.
        self.assertEqual(self.dana.request('DELETE', LLAVES + '/' + body['id'])[0], 204)
        antes = self.dana.get(LLAVES)[1]['items'][0]['last_used_at']
        postgres("UPDATE api_keys SET last_used_at = now() - interval '2 minutes' WHERE id = '%s';" % body['id'])
        self.assertEqual(self.estado(body['key']), 401)
        self.assertLess(self.dana.get(LLAVES)[1]['items'][0]['last_used_at'], antes)

    # ------------------------------------------------------------ cómo viaja y qué rutas la aceptan

    def test_8_una_llave_que_no_sirve_no_cae_a_la_cookie(self):
        llave = self.crear(self.dana)['key']
        self.assertEqual(self.dana.get('/api/v1/domains')[0], 200)
        for mala in (LLAVE_FALSA, '', 'lt_x', llave + 'x', llave[:-1], llave.upper(), ' ' + LLAVE_FALSA, llave + ' extra'):
            code, error = self.dana.get('/api/v1/domains', headers={'Authorization': 'Bearer ' + mala})
            self.assertEqual((code, error['detail']), (401, LLAVE_INVALIDA), repr(mala))
        # El esquema no distingue mayúsculas. Otro esquema no es una llave: manda la cookie, y sin cookie es 401.
        self.assertEqual(Client().get('/api/v1/domains', headers={'Authorization': 'bearer ' + llave})[0], 200)
        self.assertEqual(self.dana.get('/api/v1/domains', headers={'Authorization': 'Basic ' + llave})[0], 200)
        code, error = Client().get('/api/v1/domains', headers={'Authorization': 'Basic ' + llave})
        self.assertEqual((code, error['detail']), (401, SIN_SESION))
        # La llave no viaja en la URL, en la cookie ni en otro encabezado.
        self.assertEqual(Client().get('/api/v1/domains?api_key=' + llave)[0], 401)
        self.assertEqual(Client().get('/api/v1/domains', headers={'X-API-Key': llave})[0], 401)
        self.assertEqual(Client().get('/api/v1/domains', headers={'Cookie': 'lt_session=' + llave})[0], 401)

    def test_9_la_llave_solo_entra_a_las_lecturas(self):
        llave = self.crear(self.dana)['key']
        self.assertEqual(self.estado(llave), 200)
        cliente, encabezados = con_llave(llave)
        llave_id = self.dana.get(LLAVES)[1]['items'][0]['id']
        solo_sesion = [
            ('GET', '/api/v1/auth/me', None),
            ('POST', '/api/v1/auth/password', {'current_password': 'x', 'new_password': 'CIRDAN_FAKE_no-se-usa-1'}),
            ('GET', LLAVES, None),
            ('POST', LLAVES, {'name': 'CIRDAN_FAKE_con-llave'}),
            ('DELETE', LLAVES + '/' + llave_id, None),
            ('GET', '/api/v1/domains/txt', None),
            ('PUT', '/api/v1/scoring/weights', {'category_weights': {}}),
            ('POST', '/api/v1/domains/beta-corp.mx/action-plan/simulate', {'action_ids': ['x']}),
            ('POST', '/api/v1/domains/beta-corp.mx/scans', None),
            ('GET', '/domains', None),
            ('GET', '/domains/beta-corp.mx/findings', None),
            ('GET', '/domains/beta-corp.mx/score', None),
        ]
        for metodo, ruta, cuerpo in solo_sesion:
            code, error = cliente.request(metodo, ruta, cuerpo, encabezados)
            self.assertEqual((code, error['detail']), (401, SIN_SESION), '%s %s' % (metodo, ruta))
        # Toda escritura publicada responde 401 solo con la llave (las de iniciar sesión no piden sesión).
        _, spec = Client().get('/openapi.json')
        escrituras = [(m.upper(), ruta) for ruta, metodos in spec['paths'].items() for m in metodos
                      if m in ('post', 'put', 'patch', 'delete') and not ruta.startswith('/api/v1/auth/')]
        self.assertGreaterEqual(len(escrituras), 5)
        for metodo, ruta in escrituras:
            url = ruta.replace('{fqdn}', 'beta-corp.mx').replace('{key_id}', llave_id)
            self.assertNotIn('{', url, 'ruta con un parámetro que esta prueba no conoce')
            code, _ = cliente.request(metodo, url, {}, encabezados)
            self.assertEqual(code, 401, '%s %s' % (metodo, ruta))
        self.assertEqual(scalar("SELECT count(*) FROM api_keys WHERE revoked_at IS NULL;", user='postgres'), '1')
        self.assertEqual(self.estado(llave), 200)

    # ------------------------------------------------------------ quién y con qué plan

    def test_10_solo_el_admin_crea_lista_y_revoca(self):
        llave_id = self.crear(self.dana)['id']
        poner_plan(ACME, 'business')
        for cliente in (self.jordan, self.maya):
            self.assertEqual(cliente.post(LLAVES, {'name': 'CIRDAN_FAKE_sin-rol'})[0], 403)
            self.assertEqual(cliente.get(LLAVES)[0], 403)
            self.assertEqual(cliente.request('DELETE', LLAVES + '/' + llave_id)[0], 403)
        sin_sesion = Client()
        self.assertEqual(sin_sesion.post(LLAVES, {'name': 'CIRDAN_FAKE_sin-sesion'})[0], 401)
        self.assertEqual(sin_sesion.get(LLAVES)[0], 401)
        self.assertEqual(sin_sesion.request('DELETE', LLAVES + '/' + llave_id)[0], 401)
        self.assertEqual(scalar("SELECT count(*) FROM api_keys;", user='postgres'), '1')
        for nombre in ('', '   ', 'x' * 81, 'CIRDAN_FAKE_\u0007'):
            self.assertEqual(self.dana.post(LLAVES, {'name': nombre})[0], 422, repr(nombre))

    def test_11_solo_con_un_plan_que_incluye_la_api(self):
        # Acme es Starter: no crea.
        code, error = self.alex.post(LLAVES, {'name': 'CIRDAN_FAKE_starter'})
        self.assertEqual((code, error['detail']), (403, SIN_PLAN))
        self.assertEqual(scalar("SELECT count(*) FROM api_keys;", user='postgres'), '0')
        # Con Business crea y la llave entra. Al bajar a Starter deja de entrar, sin borrarla.
        poner_plan(ACME, 'business')
        body = self.crear(self.alex)
        self.assertEqual(self.estado(body['key']), 200)
        poner_plan(ACME, 'starter')
        code, error = get(body['key'], '/api/v1/domains')
        self.assertEqual((code, error['detail']), (401, LLAVE_INVALIDA))
        # Sin plan todavía la ve y la puede revocar.
        self.assertEqual(self.alex.get(LLAVES)[1]['items'][0]['status'], 'active')
        self.assertEqual(self.alex.request('DELETE', LLAVES + '/' + body['id'])[0], 204)
        poner_plan(ACME, 'business')
        self.assertEqual(self.estado(body['key']), 401)
        # Una empresa suspendida tampoco entra con su llave.
        otra = self.crear(self.alex, 'otra')
        self.assertEqual(self.estado(otra['key']), 200)
        postgres("UPDATE organizations SET status = 'suspended' WHERE id = '%s';" % ACME)
        self.assertEqual(self.estado(otra['key']), 401)

    def test_12_tope_de_llaves_vigentes_aunque_lleguen_a_la_vez(self):
        cookie = {'Cookie': 'lt_session=' + self.dana.cookie().value}

        def crear(i):
            return Client().post(LLAVES, {'name': 'CIRDAN_FAKE_tope_%02d' % i}, headers=cookie)[0]

        with ThreadPoolExecutor(max_workers=12) as pool:
            codigos = sorted(pool.map(crear, range(26)))
        self.assertEqual(codigos, [201] * 20 + [409] * 6)
        self.assertEqual(scalar("SELECT count(*) || ',' || count(DISTINCT key_prefix) || ',' || count(DISTINCT key_hash) "
                                "FROM api_keys;", user='postgres'), '20,20,20')
        # Las revocadas y las vencidas no cuentan.
        llave_id = self.dana.get(LLAVES)[1]['items'][0]['id']
        self.assertEqual(self.dana.request('DELETE', LLAVES + '/' + llave_id)[0], 204)
        self.crear(self.dana, 'despues-de-revocar')
        self.assertEqual(self.dana.post(LLAVES, {'name': 'CIRDAN_FAKE_de-mas'})[0], 409)

    # ------------------------------------------------------------ la base

    def test_13_api_key_lookup_con_search_path_fijo_y_solo_lo_necesario(self):
        funcion = "'public.api_key_lookup(bytea)'::regprocedure"
        config = scalar("SELECT prosecdef || ',' || array_to_string(proconfig, ';') || ','"
                        " || has_function_privilege('public', oid, 'EXECUTE') || ','"
                        " || has_function_privilege('cirdan_app', oid, 'EXECUTE') FROM pg_proc WHERE oid = %s;" % funcion)
        self.assertEqual(config, 'true,search_path=pg_catalog, public, pg_temp,false,true')
        self.assertEqual(scalar("SELECT pg_get_function_result(%s);" % funcion),
                         'TABLE(key_id uuid, organization_id uuid, domain_id uuid, scopes text[], touch boolean)')
        body = self.crear(self.dana)
        huella = hashlib.sha256(body['key'].encode()).hexdigest()
        # Sin empresa fijada, cirdan_app no ve la tabla: la función es el único camino, y solo con el hash exacto.
        self.assertEqual(scalar("SELECT count(*) FROM api_keys;"), '0')
        fila = scalar("SELECT * FROM api_key_lookup(decode('%s', 'hex'));" % huella).split('|')
        self.assertEqual(fila, [body['id'], BETA, '', '{read}', 't'])
        self.assertEqual(scalar("SELECT count(*) FROM api_key_lookup(decode('%s', 'hex'));" % huella[:-2]), '0')
        self.assertEqual(scalar("SELECT count(*) FROM api_key_lookup(NULL);"), '0')
        # Desde otra empresa tampoco se ve ni se toca, y la aplicación no cambia el hash ni el alcance.
        self.assertEqual(scalar("SELECT count(*) FROM api_keys;", org=ACME), '0')
        ok, out, _ = psql("UPDATE api_keys SET revoked_at = now() WHERE id = '%s' RETURNING 1;" % body['id'], org=ACME)
        self.assertEqual((ok, out), (True, ''))
        for columna, valor in (('key_hash', "'\\x00'"), ('key_prefix', "'lt_00000000'"), ('scopes', "'{read,write}'"),
                               ('domain_id', 'NULL'), ('organization_id', "'%s'" % ACME), ('created_at', 'now()')):
            ok, _, err = psql("UPDATE api_keys SET %s = %s WHERE id = '%s';" % (columna, valor, body['id']), org=BETA)
            self.assertFalse(ok, columna)
            self.assertIn('permission denied', err, columna)
        ok, _, err = psql("DELETE FROM api_keys WHERE id = '%s';" % body['id'], org=BETA)
        self.assertFalse(ok)
        self.assertIn('permission denied', err)
        self.assertEqual(self.estado(body['key']), 200)


if __name__ == '__main__':
    unittest.main()

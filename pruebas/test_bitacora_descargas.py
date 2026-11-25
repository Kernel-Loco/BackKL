"""Bitácora de las exportaciones (#194, RC-312) contra la API local (biblioteca estándar).

    python -m unittest -v pruebas/test_bitacora_descargas.py      (con `docker compose up -d`, DEMO_ACCOUNTS=true)

Hecho cuando de RC-312, con la decisión 1 en a (Ernesto, 17 nov): las tres exportaciones (hallazgos, comparación y plan
de acción), en CSV y en JSON, escriben report.downloaded con details de tipo, formato, dominio y número de filas, con el
usuario o la llave y la IP, en la transacción que lee los datos. Si la bitácora falla no hay descarga, details no guarda
lo exportado, la cadena de hashes de audit_log sigue íntegra y quien no puede exportar no deja evento.

Además, de la revisión de riesgo: la IP es la de la sesión (la del auth.login_succeeded del mismo usuario), un
superadmin en una empresa ajena queda con actor 'platform' (test_6), details guarda el dominio de la base aunque la ruta
traiga otras mayúsculas (test_7) y descargas a la vez dejan cada una su evento sin romper la cadena (test_8).

Las llaves que crea se llaman CIRDAN_FAKE_... y las limpia borrar_llaves() de test_llaves_api.py. El trigger que hace
fallar la bitácora se crea y se borra dentro de la prueba 4, y setUpClass borra uno que haya quedado de una corrida
cortada. Dana es superadmin solo durante la prueba 6.
"""
import csv
import io
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request

from pruebas import sesion
from pruebas.test_aislamiento import ACME, BETA, psql, scalar
from pruebas.test_llaves_api import borrar_llaves, poner_plan
from pruebas.test_superadmin import CAMBIO, DANA_ID, hacer_superadmin, quitar_superadmin

ALEX = 'alex.morgan@acme-demo.mx'     # admin de Acme
JORDAN = 'jordan.tate@acme-demo.mx'   # analista de Acme
DANA = 'dana.cruz@beta-corp.mx'       # admin de Beta (Business)
COMPARAR = 'desde=a0000000-0000-4000-8000-000000000001&hasta=a0000000-0000-4000-8000-000000000004'
EXPORTACIONES = (  # (tipo en details, ruta sin formato)
    ('findings', '/api/v1/domains/acme-demo.mx/findings/export?'),
    ('comparison', '/api/v1/domains/acme-demo.mx/score/compare/export?' + COMPARAR + '&'),
    ('action_plan', '/api/v1/domains/acme-demo.mx/action-plan/export?'),
)
CAMPOS_DETAILS = {'kind', 'format', 'domain', 'rows'}
QUITAR_FALLA = ('DROP TRIGGER IF EXISTS rc312_falla ON public.audit_log; '
                'DROP FUNCTION IF EXISTS public.rc312_falla();')

# La cadena se recalcula como el trigger audit_log_chain() de la 001: consecutivo sin huecos, prev_hash igual al
# row_hash anterior (génesis en ceros) y row_hash igual al SHA-256 del contenido canónico. Cuenta las filas que fallan.
CADENA_ROTA = r'''
SELECT count(*) FROM (
  SELECT l.*, lag(l.row_hash) OVER w AS anterior, lag(l.chain_seq) OVER w AS seq_anterior
    FROM audit_log l WHERE l.organization_id = '%s' WINDOW w AS (ORDER BY l.chain_seq)) x
 WHERE x.chain_seq <> coalesce(x.seq_anterior, 0) + 1
    OR x.prev_hash <> coalesce(x.anterior, decode(repeat('00', 32), 'hex'))
    OR x.row_hash <> sha256(x.prev_hash || convert_to(concat_ws(chr(31),
         coalesce(x.organization_id::text, ''), x.chain_seq::text, x.id::text,
         (extract(epoch FROM x.occurred_at) * 1000000)::bigint::text,
         x.actor_type, coalesce(x.actor_user_id::text, ''), coalesce(x.actor_api_key_id::text, ''),
         x.action, coalesce(x.entity_type, ''), coalesce(x.entity_id::text, ''), x.details::text), 'UTF8'));
'''


def ultimo_seq(org):
    return int(scalar("SELECT coalesce(max(chain_seq), 0) FROM audit_log WHERE organization_id = '%s';" % org,
                      user='postgres'))


def eventos(org, desde):
    """Los report.downloaded de la empresa después de chain_seq = desde, en orden."""
    out = scalar('''
        SELECT coalesce(json_agg(json_build_object(
                 'actor_type', actor_type, 'actor_user_id', actor_user_id, 'actor_api_key_id', actor_api_key_id,
                 'entity_type', entity_type, 'entity_id', entity_id, 'ip', host(ip_address), 'details', details)
                 ORDER BY chain_seq), '[]')
          FROM audit_log WHERE organization_id = '%s' AND chain_seq > %d AND action = 'report.downloaded';
    ''' % (org, desde), user='postgres')
    return json.loads(out)


def ip_de_sesion(user_id):
    """La IP con la que entró el usuario: la del último auth.login_succeeded suyo."""
    return scalar("SELECT host(ip_address) FROM audit_log WHERE action = 'auth.login_succeeded' AND actor_user_id = '%s'"
                  " ORDER BY occurred_at DESC, chain_seq DESC LIMIT 1;" % user_id, user='postgres')


def descargar(url, client=None, llave=None):
    """(código, texto) de una descarga, con la cookie del cliente o con la llave."""
    req = urllib.request.Request(sesion.BASE + url, headers={'Authorization': 'Bearer ' + llave} if llave else {})
    opener = client.opener if client else urllib.request.build_opener()
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, r.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')


def filas(tipo, formato, texto):
    """Las filas de datos de la descarga: renglones del CSV sin encabezado, o items y acciones del JSON."""
    if formato == 'csv':
        return len(list(csv.reader(io.StringIO(texto.lstrip('\ufeff'), newline='')))) - 1
    data = json.loads(texto)
    return len(data['actions']) if tipo == 'action_plan' else data['total']


class BitacoraDescargas(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ok, _, err = psql(QUITAR_FALLA, user='postgres')  # el de una corrida cortada antes del finally de test_4
        assert ok, err
        sesion.reset()
        borrar_llaves()
        cls.alex = sesion.login(ALEX)
        cls.jordan = sesion.login(JORDAN)
        cls.beta = sesion.login(DANA)
        cls.alex_id = scalar("SELECT id FROM users WHERE email = '%s';" % ALEX, user='postgres')
        cls.jordan_id = scalar("SELECT id FROM users WHERE email = '%s';" % JORDAN, user='postgres')
        cls.acme_demo = scalar("SELECT id FROM domains WHERE fqdn = 'acme-demo.mx';", user='postgres')
        cls.ip = ip_de_sesion(cls.alex_id)
        assert cls.ip and cls.ip == ip_de_sesion(cls.jordan_id), (cls.ip, ip_de_sesion(cls.jordan_id))

    def tearDown(self):
        poner_plan(ACME, 'starter')
        borrar_llaves()

    def assertCadenaIntegra(self, org):
        self.assertEqual(scalar(CADENA_ROTA % org, user='postgres'), '0', org)

    def test_1_cada_exportacion_en_csv_y_json_deja_su_evento(self):
        for cliente, usuario in ((self.alex, self.alex_id), (self.jordan, self.jordan_id)):  # admin y analista
            for tipo, ruta in EXPORTACIONES:
                for formato in ('csv', 'json'):
                    antes = ultimo_seq(ACME)
                    code, texto = descargar(ruta + 'formato=' + formato, cliente)
                    self.assertEqual(code, 200, (tipo, formato, texto))
                    nuevos = eventos(ACME, antes)
                    self.assertEqual(len(nuevos), 1, (tipo, formato, nuevos))
                    e = nuevos[0]
                    self.assertEqual(e['details'], {'kind': tipo, 'format': formato, 'domain': 'acme-demo.mx',
                                                    'rows': filas(tipo, formato, texto)}, (tipo, formato))
                    self.assertEqual((e['actor_type'], e['actor_user_id'], e['actor_api_key_id']),
                                     ('user', usuario, None), (tipo, formato))
                    self.assertEqual((e['entity_type'], e['entity_id']), ('domain', self.acme_demo), (tipo, formato))
                    self.assertEqual(e['ip'], ip_de_sesion(usuario), (tipo, formato))
        self.assertCadenaIntegra(ACME)

    def test_2_details_no_guarda_lo_exportado(self):
        antes = ultimo_seq(ACME)
        code, texto = descargar('/api/v1/domains/acme-demo.mx/findings/export?formato=json', self.alex)
        self.assertEqual(code, 200)
        items = json.loads(texto)['items']
        self.assertTrue(items)
        (e,) = eventos(ACME, antes)
        self.assertEqual(set(e['details']), CAMPOS_DETAILS)
        guardado = json.dumps(e['details'])
        for i in items:  # el activo puede ser el dominio mismo, que sí va en details
            for valor in (i['id'], i['title'], i['asset'] if i['asset'] != 'acme-demo.mx' else None):
                if valor:
                    self.assertNotIn(str(valor), guardado)

    def test_3_con_llave_de_api_el_actor_es_la_llave(self):
        code, body = self.beta.post('/api/v1/api-keys', {'own_use': True, 'name': 'CIRDAN_FAKE_rc312'})
        self.assertEqual(code, 201, body)
        for formato in ('csv', 'json'):
            antes = ultimo_seq(BETA)
            code, texto = descargar('/api/v1/domains/beta-corp.mx/findings/export?formato=' + formato,
                                    llave=body['key'])
            self.assertEqual(code, 200, texto)
            (e,) = eventos(BETA, antes)
            # La llave va en details y no en actor_api_key_id, cuya FK no dejaría borrarla (decisión del 17 nov).
            self.assertEqual((e['actor_type'], e['actor_user_id'], e['actor_api_key_id']), ('api_key', None, None))
            self.assertEqual(e['details'], {'kind': 'findings', 'format': formato, 'domain': 'beta-corp.mx',
                                            'rows': filas('findings', formato, texto), 'api_key_id': body['id']})
            self.assertEqual(e['ip'], self.ip)  # la llave no inicia sesión: es la IP de este mismo cliente
        self.assertCadenaIntegra(BETA)
        ok, _, err = psql("DELETE FROM api_keys WHERE id = '%s';" % body['id'], user='postgres')
        self.assertTrue(ok, err)

    def test_4_si_la_bitacora_falla_no_hay_descarga(self):
        # Un trigger de prueba hace fallar el INSERT de report.downloaded. La transacción se deshace: 500 sin el
        # contenido y sin evento. Se borra al terminar.
        crear = '''
            CREATE FUNCTION public.rc312_falla() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'rc312: bitácora caída'; END $$;
            CREATE TRIGGER rc312_falla BEFORE INSERT ON public.audit_log FOR EACH ROW
              WHEN (NEW.action = 'report.downloaded') EXECUTE FUNCTION public.rc312_falla();
        '''
        ok, _, err = psql(QUITAR_FALLA + crear, user='postgres')
        self.assertTrue(ok, err)
        try:
            for tipo, ruta in EXPORTACIONES:
                for formato in ('csv', 'json'):
                    antes = ultimo_seq(ACME)
                    code, texto = descargar(ruta + 'formato=' + formato, self.alex)
                    self.assertEqual(code, 500, (tipo, formato))
                    self.assertNotIn('acme-demo.mx', texto, (tipo, formato))
                    self.assertEqual(ultimo_seq(ACME), antes, (tipo, formato))
        finally:
            ok, _, err = psql(QUITAR_FALLA, user='postgres')
        self.assertTrue(ok, err)  # fuera del finally: si la descarga falló, se ve esa falla y no esta
        self.assertCadenaIntegra(ACME)

    def test_5_quien_no_puede_exportar_no_deja_evento(self):
        poner_plan(ACME, 'business')
        code, tienda = self.alex.post('/api/v1/api-keys', {'own_use': True, 'name': 'CIRDAN_FAKE_rc312_tienda',
                                                            'domain': 'acme-tienda.mx'})
        self.assertEqual(code, 201, tienda)
        code, revocada = self.alex.post('/api/v1/api-keys', {'own_use': True, 'name': 'CIRDAN_FAKE_rc312_revocada'})
        self.assertEqual(code, 201, revocada)
        self.assertEqual(self.alex.request('DELETE', '/api/v1/api-keys/' + revocada['id'])[0], 204)
        sin_carta = ('/api/v1/domains/old-example.net/findings/export?formato=csv',  # carta vencida el 15 ago
                     '/api/v1/domains/old-example.net/score/compare/export?formato=json&' + COMPARAR,
                     '/api/v1/domains/old-example.net/action-plan/export?formato=csv')  # RC-307
        casos = [(None, None, ruta + 'formato=csv', 401) for _, ruta in EXPORTACIONES]   # sin sesión
        casos += [(self.beta, None, ruta + 'formato=json', 404) for _, ruta in EXPORTACIONES]   # otra empresa
        casos += [(None, tienda['key'], ruta + 'formato=json', 404) for _, ruta in EXPORTACIONES]   # otro dominio
        casos += [(None, revocada['key'], ruta + 'formato=json', 401) for _, ruta in EXPORTACIONES]   # revocada
        casos += [(self.alex, None, ruta + 'formato=xlsx', 422) for _, ruta in EXPORTACIONES]   # formato que no hay
        casos += [(self.alex, None, url, 403) for url in sin_carta]
        acme, beta = ultimo_seq(ACME), ultimo_seq(BETA)
        for cliente, llave, url, esperado in casos:
            self.assertEqual(descargar(url, cliente, llave)[0], esperado, url)
        self.assertEqual((eventos(ACME, acme), eventos(BETA, beta)), ([], []))

    def test_6_superadmin_en_empresa_ajena_queda_como_platform(self):
        # RC-332: sin actor_user_id (la FK pide un usuario de Acme) y con su id en details.
        self.addCleanup(quitar_superadmin, DANA_ID)
        hacer_superadmin(DANA_ID)
        dana = sesion.login(DANA)
        self.assertEqual(dana.post(CAMBIO, {'organization_id': ACME})[0], 200)
        self.addCleanup(dana.post, CAMBIO, {'organization_id': BETA})
        for tipo, ruta in EXPORTACIONES:
            for formato in ('csv', 'json'):
                antes = ultimo_seq(ACME)
                code, texto = descargar(ruta + 'formato=' + formato, dana)
                self.assertEqual(code, 200, (tipo, formato, texto))
                (e,) = eventos(ACME, antes)
                self.assertEqual((e['actor_type'], e['actor_user_id'], e['actor_api_key_id']),
                                 ('platform', None, None), (tipo, formato))
                self.assertEqual(e['details'], {'kind': tipo, 'format': formato, 'domain': 'acme-demo.mx',
                                                'rows': filas(tipo, formato, texto), 'platform_user_id': DANA_ID})
                self.assertEqual(e['ip'], ip_de_sesion(DANA_ID), (tipo, formato))
        self.assertCadenaIntegra(ACME)

    def test_7_details_guarda_el_dominio_de_la_base(self):
        # fqdn es citext y la ruta acepta otras mayúsculas, pero un filtro por details->>'domain' compara texto exacto.
        for tipo, ruta in EXPORTACIONES:
            antes = ultimo_seq(ACME)
            code, _ = descargar(ruta.replace('acme-demo.mx', 'ACME-Demo.MX') + 'formato=json', self.alex)
            self.assertEqual(code, 200, tipo)
            (e,) = eventos(ACME, antes)
            self.assertEqual(e['details']['domain'], 'acme-demo.mx', tipo)

    def test_8_descargas_a_la_vez_dejan_cada_una_su_evento(self):
        antes = ultimo_seq(ACME)
        urls = [ruta + 'formato=' + f for _, ruta in EXPORTACIONES for f in ('csv', 'json')] * 2
        clientes = [self.alex, self.jordan] * (len(urls) // 2)
        with ThreadPoolExecutor(max_workers=len(urls)) as hilos:
            codigos = list(hilos.map(lambda par: descargar(*par)[0], zip(urls, clientes)))
        self.assertEqual(codigos, [200] * len(urls))
        self.assertEqual(len(eventos(ACME, antes)), len(urls))
        self.assertCadenaIntegra(ACME)


if __name__ == '__main__':
    unittest.main()

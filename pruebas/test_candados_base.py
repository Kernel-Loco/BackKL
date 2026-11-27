"""Candados de la base para el escaneo, la bitácora, las cartas y el TXT (migraciones 035, 036 y 037; RC-285, RC-294
y RC-272).

Corren contra la base `cirdan` del compose desechable (pruebas/pila.py), nunca contra `cirdan-pg16`, entrando como
`cirdan_app` y, donde hace falta saltar un permiso, como `postgres`, igual que test_aislamiento.py. Solo usan la
biblioteca estándar:

    python -m unittest -v pruebas/test_candados_base.py

Todo corre dentro de una transacción que se deshace, así que la base queda igual.
"""
import hashlib
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # también corre como python pruebas/test_candados_base.py

from cirdan import bitacora  # noqa: E402
from pruebas.test_aislamiento import ACME, psql, scalar  # noqa: E402

RAIZ = Path(__file__).resolve().parents[1]
ESCANEO = '60000000-0000-4000-8000-000000000001'       # acme-demo.mx, completado (semilla 001)
DOMINIO = '40000000-0000-4000-8000-000000000001'       # acme-demo.mx
CARTA = '41000000-0000-4000-8000-000000000001'         # vigente hasta el 31 dic 2026
CARTA_TIENDA = '41000000-0000-4000-8000-000000000002'  # acme-tienda.mx, otro dominio
DOMINIO_VIEJO = '40000000-0000-4000-8000-000000000005'  # old-example.net, su carta 41...05 venció el 15 ago 2026
CARTA_VIEJA = '41000000-0000-4000-8000-000000000005'
USUARIO = '30000000-0000-4000-8000-000000000001'
NUEVA = '41000000-0000-4000-8000-0000000285ff'
TXT_ACME = 'cirdan-verification=c41d7e2a9b06'
SPF_LOWTIDE = 'v=spf1 include:_spf.mx.cloudflare.net -all'


def huella(texto):
    return 'sha256:' + hashlib.sha256(texto.encode('utf-8')).hexdigest()


def carta(desde, hasta, dominio=DOMINIO, id_=NUEVA):
    """SQL que carga una carta de prueba de Acme, con fechas en SQL (por ejemplo 'current_date + 1')."""
    return ("INSERT INTO domain_authorizations (id, organization_id, domain_id, signer_name, signer_title, signer_email,"
            " signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by) VALUES"
            " ('%s', '%s', '%s', 'Prueba', 'Prueba', 'prueba@acme-demo.mx', 'authorizations/prueba/%s.pdf',"
            " sha256('prueba'), %s, %s, '%s');" % (id_, ACME, dominio, id_, desde, hasta, USUARIO))


def rollback(sql):
    return 'BEGIN;\n' + sql + '\nROLLBACK;'


class Escaneo(unittest.TestCase):
    """RC-285: un escaneo ya creado no cambia de carta, TXT, dominio ni fecha."""

    INMUTABLES = (('authorization_id', "'%s'" % CARTA_TIENDA), ('txt_verification_id', "'42000000-0000-4000-8000-000000000002'"),
                  ('domain_id', "'40000000-0000-4000-8000-000000000002'"), ('queued_at', "now() - interval '1 day'"),
                  ('trigger_type', "'on_demand'"), ('requested_by', "'%s'" % USUARIO))

    def test_1_la_app_solo_tiene_update_en_las_cuatro_columnas(self):
        self.assertEqual(scalar("SELECT has_table_privilege('cirdan_app', 'scans', 'UPDATE');", user='postgres'), 'f')
        columnas = scalar("SELECT string_agg(attname, ',' ORDER BY attname) FROM pg_attribute WHERE attrelid = "
                          "'scans'::regclass AND attnum > 0 AND NOT attisdropped AND "
                          "has_column_privilege('cirdan_app', 'scans', attname, 'UPDATE');", user='postgres')
        self.assertEqual(columnas, 'finished_at,stats,status,updated_at')

    def test_2_la_app_no_cambia_carta_txt_dominio_ni_fecha(self):
        for columna, valor in self.INMUTABLES:
            with self.subTest(columna=columna):
                ok, _, err = psql(rollback("UPDATE scans SET %s = %s WHERE id = '%s';" % (columna, valor, ESCANEO)),
                                  org=ACME)
                self.assertFalse(ok)
                self.assertIn('permission denied', err)

    def test_3_postgres_tampoco(self):
        for columna, valor in self.INMUTABLES + (('organization_id', "'20000000-0000-4000-8000-000000000002'"),):
            with self.subTest(columna=columna):
                ok, _, err = psql(rollback("UPDATE scans SET %s = %s WHERE id = '%s';" % (columna, valor, ESCANEO)),
                                  user='postgres')
                self.assertFalse(ok)
                self.assertIn('solo cambia status, finished_at, stats y updated_at', err)

    def test_4_el_cierre_y_la_marca_de_vida_siguen(self):
        ok, out, err = psql(rollback(
            "UPDATE scans SET status = 'failed', finished_at = now(), stats = '{\"x\": 1}', updated_at = now()"
            " WHERE id = '%s' RETURNING status || ',' || (stats->>'x');" % ESCANEO), org=ACME)
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-1], 'failed,1')


class Bitacora(unittest.TestCase):
    """RC-294: la IP entra en la cadena y la app no fija la hora ni los campos de la cadena."""

    def verificar(self, preparar):
        """El resultado de VERIFICAR_SQL de Acme después de `preparar`, como postgres y en una transacción que se
        deshace: (motivo, id roto) o ('intacta', '')."""
        consulta = ("SELECT coalesce(r.broken_reason, 'intacta') || ',' || coalesce(r.broken_id, '') FROM ("
                    + bitacora.VERIFICAR_SQL + ") r;")
        ok, out, err = psql(rollback(preparar + '\n' + consulta), user='postgres', org=ACME)
        self.assertTrue(ok, err)
        return tuple(out.splitlines()[-1].split(','))

    def evento(self, id_, ip="'203.0.113.7'", hora=None):
        hora_col, hora_val = (', occurred_at', ", %s" % hora) if hora else ('', '')
        return ("INSERT INTO audit_log (id, organization_id, actor_type, action, entity_type, details, ip_address%s)"
                " VALUES ('%s', '%s', 'system', 'prueba.rc294', 'prueba', '{}', %s%s);" % (hora_col, id_, ACME, ip,
                                                                                          hora_val))

    def test_5_la_app_no_fija_la_hora_ni_la_cadena(self):
        for columna, valor in (('occurred_at', "now() - interval '1 day'"), ('chain_seq', '1'),
                               ('chain_version', '1'), ('row_hash', "'\\x00'"), ('prev_hash', "'\\x00'"),
                               ('id', "gen_random_uuid()"), ('created_at', 'now()')):
            with self.subTest(columna=columna):
                ok, _, err = psql(rollback(
                    "INSERT INTO audit_log (organization_id, actor_type, action, details, %s) VALUES ('%s', 'system',"
                    " 'prueba.rc294', '{}', %s);" % (columna, ACME, valor)), org=ACME)
                self.assertFalse(ok)
                self.assertIn('permission denied', err)

    def test_6_sin_esos_campos_entra_con_la_version_2_y_la_ip(self):
        ok, out, err = psql(rollback(
            "INSERT INTO audit_log (organization_id, actor_type, action, details, ip_address) VALUES ('%s', 'system',"
            " 'prueba.rc294', '{}', '203.0.113.7') RETURNING chain_version || ',' || host(ip_address)"
            " || ',' || (occurred_at > now() - interval '1 minute');" % ACME), org=ACME)
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-1], '2,203.0.113.7,true')

    def test_7_cambiar_la_ip_de_una_fila_nueva_rompe_la_cadena(self):
        uno = 'c0000000-0000-4000-8000-0000000294f1'
        self.assertEqual(self.verificar(self.evento(uno)), ('intacta', ''))
        cambios = ("ALTER TABLE audit_log DISABLE TRIGGER audit_log_block_ud;\n%s\n"
                   "ALTER TABLE audit_log ENABLE TRIGGER audit_log_block_ud;")
        for cambio in ("UPDATE audit_log SET ip_address = '203.0.113.8' WHERE id = '%s';" % uno,
                       "UPDATE audit_log SET ip_address = NULL WHERE id = '%s';" % uno,
                       "UPDATE audit_log SET ip_address = '203.0.113.7/24' WHERE id = '%s';" % uno,
                       "UPDATE audit_log SET chain_version = 1 WHERE id = '%s';" % uno):
            with self.subTest(cambio=cambio):
                self.assertEqual(self.verificar(self.evento(uno) + '\n' + cambios % cambio), ('row_hash', uno))

    def test_8_una_fila_de_antes_de_la_036_sigue_verificando(self):
        """Una fila de la versión 1, con su row_hash de la fórmula de la 001, cuadra. Su IP no entraba en el hash."""
        uno = 'c0000000-0000-4000-8000-0000000294f2'
        v1 = bitacora.HASH_FILA.replace('CASE chain_version', 'CASE 1')
        a_v1 = ("ALTER TABLE audit_log DISABLE TRIGGER audit_log_block_ud;\n"
                "UPDATE audit_log SET chain_version = 1, row_hash = %s WHERE id = '%s';\n"
                "ALTER TABLE audit_log ENABLE TRIGGER audit_log_block_ud;" % (v1, uno))
        self.assertEqual(self.verificar(self.evento(uno) + '\n' + a_v1), ('intacta', ''))
        ip = ("ALTER TABLE audit_log DISABLE TRIGGER audit_log_block_ud;\n"
              "UPDATE audit_log SET ip_address = '203.0.113.9' WHERE id = '%s';\n"
              "ALTER TABLE audit_log ENABLE TRIGGER audit_log_block_ud;" % uno)
        self.assertEqual(self.verificar(self.evento(uno) + '\n' + a_v1 + '\n' + ip), ('intacta', ''))
        # /verify dice cuántas filas son de la versión 1, y la lista trae la versión de cada fila.
        v1s = 'SELECT r.checked_v1 FROM (' + bitacora.VERIFICAR_SQL + ') r;'
        lista = "SELECT chain_version FROM (" + bitacora.LISTA_SQL % (1, 0) + ") l;"
        ok, antes, err = psql(rollback(self.evento(uno) + '\n' + v1s + '\n' + lista), user='postgres', org=ACME)
        self.assertTrue(ok, err)
        ok, despues, err = psql(rollback(self.evento(uno) + '\n' + a_v1 + '\n' + v1s + '\n' + lista), user='postgres',
                                org=ACME)
        self.assertTrue(ok, err)
        self.assertEqual(int(despues.splitlines()[-2]), int(antes.splitlines()[-2]) + 1)
        self.assertEqual((antes.splitlines()[-1], despues.splitlines()[-1]), ('2', '1'))

    def test_9_una_hora_fuera_de_orden_no_rompe_la_cadena(self):
        dos = (self.evento('c0000000-0000-4000-8000-0000000294f3', hora="now()") + '\n' +
               self.evento('c0000000-0000-4000-8000-0000000294f4', hora="now() - interval '5 milliseconds'"))
        self.assertEqual(self.verificar(dos), ('intacta', ''))


class Cartas(unittest.TestCase):
    """RC-272: una carta nueva revoca la anterior y una revocación no se deshace."""

    def test_10_una_revocacion_no_se_deshace_ni_cambia_de_fecha(self):
        revocar = "UPDATE domain_authorizations SET revoked_at = now() WHERE id = '%s';" % CARTA
        for usuario in ('cirdan_app', 'postgres'):
            for cambio in ('NULL', "now() - interval '1 day'", "now() + interval '1 day'"):
                with self.subTest(usuario=usuario, cambio=cambio):
                    ok, _, err = psql(rollback(revocar + "\nUPDATE domain_authorizations SET revoked_at = %s"
                                                         " WHERE id = '%s';" % (cambio, CARTA)), user=usuario, org=ACME)
                    self.assertFalse(ok)
                    self.assertIn('una revocación no se deshace ni cambia de fecha', err)
        # Revocar y dejar la misma fecha sí pasan, y lo demás de la carta sigue inmutable.
        ok, out, err = psql(rollback(revocar + "\nUPDATE domain_authorizations SET revoked_at = revoked_at WHERE id ="
                                               " '%s' RETURNING revoked_at IS NOT NULL;" % CARTA), org=ACME)
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-1], 't')
        ok, _, err = psql(rollback("UPDATE domain_authorizations SET valid_until = '2030-01-01' WHERE id = '%s';"
                                   % CARTA), user='postgres')
        self.assertFalse(ok)
        self.assertIn('es inmutable', err)

    def test_11_una_carta_nueva_revoca_la_anterior_y_deja_el_evento(self):
        ok, out, err = psql(rollback(carta('current_date - 1', 'current_date + 30') + """
SELECT string_agg(id::text || ':' || (revoked_at IS NOT NULL), ',' ORDER BY id) FROM domain_authorizations
 WHERE id IN ('%(carta)s', '%(nueva)s');
SELECT (revoked_at IS NULL)::text FROM domain_authorizations WHERE id = '%(tienda)s';
SELECT (SELECT revoked_at FROM domain_authorizations WHERE id = '%(carta)s') = now();
SELECT string_agg(actor_type || ',' || entity_type || ',' || entity_id || ',' || (details->>'replaced_by')
                  || ',' || chain_version, ';')
  FROM audit_log WHERE action = 'authorization.superseded' AND details->>'replaced_by' = '%(nueva)s';"""
            % {'tienda': CARTA_TIENDA, 'carta': CARTA, 'nueva': NUEVA}), org=ACME)
        self.assertTrue(ok, err)
        filas = out.splitlines()[-4:]
        self.assertEqual(filas[0], '%s:true,%s:false' % (CARTA, NUEVA))
        self.assertEqual(filas[1], 'true')         # otro dominio no cambia
        self.assertEqual(filas[2], 't')            # con la hora de la carga
        self.assertEqual(filas[3], 'system,domain_authorization,%s,%s,2' % (CARTA, NUEVA))

    def test_12_una_carta_futura_no_entra_con_otra_vigente(self):
        for usuario in ('cirdan_app', 'postgres'):
            with self.subTest(usuario=usuario):
                ok, _, err = psql(rollback(carta('current_date + 1', 'current_date + 30')), user=usuario, org=ACME)
                self.assertFalse(ok)
                self.assertIn('se carga el día que empieza', err)
        # La que empieza hoy sí entra.
        ok, _, err = psql(rollback(carta('current_date', 'current_date + 30')), org=ACME)
        self.assertTrue(ok, err)

    def test_13_una_carta_futura_entra_si_la_anterior_ya_vencio(self):
        ok, out, err = psql(rollback(carta('current_date + 1', 'current_date + 30', dominio=DOMINIO_VIEJO) +
                                     "\nSELECT (revoked_at IS NOT NULL)::text FROM domain_authorizations WHERE id = '%s';"
                                     % CARTA_VIEJA), org=ACME)
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-1], 'true')

    def test_13b_una_carta_vencida_no_revoca_la_vigente(self):
        """Una carta que ya venció al cargarse (a mano: la API da 422) no deja al dominio sin su carta vigente."""
        ok, out, err = psql(rollback(carta('current_date - 30', 'current_date - 1') +
                                     "\nSELECT (revoked_at IS NULL)::text FROM domain_authorizations WHERE id = '%s';"
                                     "\nSELECT count(*) FROM audit_log WHERE action = 'authorization.superseded'"
                                     " AND details->>'replaced_by' = '%s';" % (CARTA, NUEVA)), org=ACME)
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-2:], ['true', '0'])

    def test_13c_dos_cartas_del_mismo_dominio_en_una_sentencia_se_rechazan(self):
        """Si no, cada una revocaría a la otra para siempre. En dos sentencias, la segunda revoca a la primera."""
        otra = '41000000-0000-4000-8000-0000000285fe'
        dos = carta('current_date', 'current_date + 30').rstrip(';') + carta(
            'current_date', 'current_date + 60', id_=otra).split(' VALUES', 1)[1].replace(' (', ', (', 1)
        for usuario in ('cirdan_app', 'postgres'):
            with self.subTest(usuario=usuario):
                ok, _, err = psql(rollback(dos), user=usuario, org=ACME)
                self.assertFalse(ok)
                self.assertIn('se cargan una por una', err)
        ok, out, err = psql(rollback(carta('current_date', 'current_date + 30') + '\n' +
                                     carta('current_date', 'current_date + 60', id_=otra) +
                                     "\nSELECT string_agg(id::text || ':' || (revoked_at IS NOT NULL), ',' ORDER BY id)"
                                     " FROM domain_authorizations WHERE id IN ('%s', '%s');" % (otra, NUEVA)), org=ACME)
        self.assertTrue(ok, err)
        self.assertEqual(out.splitlines()[-1], '%s:false,%s:true' % (otra, NUEVA))

    def test_14_hoy_es_el_de_la_ciudad_de_mexico(self):
        """El trigger compara con la fecha de la Ciudad de México aunque la sesión esté en otra zona: a las 20:00 de
        Monterrey ya es mañana en UTC."""
        for funcion in ('domain_authorizations_una_vigente', 'domain_authorizations_reemplaza'):
            with self.subTest(funcion=funcion):
                self.assertEqual(scalar("SELECT array_to_string(proconfig, ',') FROM pg_proc"
                                        " WHERE oid = '%s'::regproc;" % funcion, user='postgres'),
                                 'TimeZone=America/Mexico_City')


class Txt(unittest.TestCase):
    """RC-272: observed_values solo guarda el valor de verificación y la huella de lo demás."""

    def insertar(self, valores):
        return ("INSERT INTO dns_txt_verifications (organization_id, domain_id, check_reason, expected_value,"
                " observed_values, resolver_ip, result, checked_at) VALUES ('%s', '%s', 'pre_scan', '%s', %s,"
                " '1.1.1.1', 'match', now());" % (ACME, DOMINIO, TXT_ACME, valores))

    def test_15_el_check_rechaza_un_txt_crudo(self):
        for valores in ("ARRAY['v=spf1 -all']", "ARRAY['%s', 'google-site-verification=abc']" % TXT_ACME,
                        "ARRAY['cirdan-verification=C41D7E2A9B06']", "ARRAY['sha256:%s']" % ('a' * 63),
                        "ARRAY['%s', NULL]" % TXT_ACME):
            with self.subTest(valores=valores):
                ok, _, err = psql(rollback(self.insertar(valores)), org=ACME)
                self.assertFalse(ok)
                self.assertIn('dns_txt_verifications_observed_values_check', err)

    def test_16_el_check_deja_pasar_el_token_y_las_huellas(self):
        for valores in ("ARRAY['%s', '%s']" % (huella('v=spf1 -all'), TXT_ACME), 'NULL', "'{}'"):
            with self.subTest(valores=valores):
                ok, _, err = psql(rollback(self.insertar(valores)), org=ACME)
                self.assertTrue(ok, err)

    def test_17_no_queda_ningun_txt_crudo_y_el_spf_de_lowtide_va_como_huella(self):
        self.assertEqual(scalar("SELECT count(*) FROM dns_txt_verifications WHERE NOT"
                                " txt_observados_validos(observed_values);", user='postgres'), '0')
        self.assertEqual(scalar("SELECT observed_values::text FROM dns_txt_verifications WHERE id ="
                                " '42000000-0000-4000-8000-000000000008';", user='postgres'),
                         '{%s,cirdan-verification=be92b38a1634}' % huella(SPF_LOWTIDE))

    def test_18_la_037_reescribe_las_filas_viejas_en_su_orden(self):
        """La sección 5 de la 037, tal cual, sobre una fila cruda: el token queda, lo demás pasa a su huella con el
        mismo cálculo que guardables() del orquestador, sin los NULL y en el mismo orden. Su trigger queda encendido."""
        texto = (RAIZ / 'db' / 'migraciones' / '037_cartas_y_txt.sql').read_text(encoding='utf-8')
        seccion = re.search(r'-- 5\. Las filas que ya existen, con el mismo filtro -+\n(.*?)\nCOMMENT ON COLUMN', texto,
                            re.S).group(1)
        fila = '42000000-0000-4000-8000-0000000272ff'
        sql = ("ALTER TABLE dns_txt_verifications DROP CONSTRAINT dns_txt_verifications_observed_values_check;\n"
               "INSERT INTO dns_txt_verifications (id, organization_id, domain_id, check_reason, expected_value,"
               " observed_values, resolver_ip, result, checked_at) VALUES ('%s', '%s', '%s', 'pre_scan', '%s',"
               " ARRAY['v=spf1 -all', '%s', NULL, 'ñandú=1'], '1.1.1.1', 'match', now());\n%s\n"
               "SELECT observed_values::text || '|' || result FROM dns_txt_verifications WHERE id = '%s';\n"
               "UPDATE dns_txt_verifications SET result = 'mismatch' WHERE id = '%s';"
               % (fila, ACME, DOMINIO, TXT_ACME, TXT_ACME, seccion, fila, fila))
        ok, out, err = psql(rollback(sql), user='postgres')
        self.assertFalse(ok)                                   # el UPDATE final: el trigger volvió
        self.assertIn('de solo inserción', err)
        esperado = [huella('v=spf1 -all'), TXT_ACME, huella('ñandú=1')]
        self.assertEqual(out.splitlines()[-1], '{%s}|match' % ','.join(esperado))


if __name__ == '__main__':
    unittest.main(verbosity=2)

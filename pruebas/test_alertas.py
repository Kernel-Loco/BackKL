"""Outbox y entrega de alertas a Teams (#65, RC-114) contra la base, dentro del contenedor de la API.

    docker compose run --rm -e CIRDAN_TEST_DB_ISOLATED=true -v "$PWD/pruebas:/app/pruebas:ro" api \
        python -m unittest -v pruebas/test_alertas.py

Todo corre en una transacción que se deshace al final. El flujo de Teams es una función simulada: no sale nada a la red.
El gancho en el orquestador (un crítico nuevo deja su alerta en la transacción del hallazgo) se prueba en
pruebas/test_orquestador.py (test_2t).
"""
import unittest
import uuid

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from cirdan.alertas import outbox, tarjeta
from cirdan.db import DSN
from pruebas.pila import exigir_desechable

ACME = '20000000-0000-4000-8000-000000000001'
DOMINIO = '40000000-0000-4000-8000-000000000001'      # acme-demo.mx
CRITICO = '80000000-0000-4000-8000-000000000001'      # brecha crítica abierta de la semilla
URL = ('https://prod-12.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?api-version=1'
       '&sig=CIRDAN_FAKE_firma')


def integracion(conn, url=URL, encendida=True):
    id_ = str(uuid.uuid4())
    conn.execute("INSERT INTO integrations (id, organization_id, kind, name, endpoint, secret_enc, config, enabled) "
                 "VALUES (%s, %s, 'webhook', 'Microsoft Teams', %s, %s, %s, %s)",
                 (id_, ACME, tarjeta.validar_url(url), outbox.cifrar_url(id_, url), Jsonb({'formato': 'teams'}),
                  encendida))
    return id_


class Alertas(unittest.TestCase):

    def setUp(self):
        exigir_desechable()   # dentro del contenedor solo con CIRDAN_TEST_DB_ISOLATED=true
        self.conn = psycopg.connect(DSN, row_factory=dict_row)
        self.tx = self.conn.transaction(force_rollback=True)
        self.tx.__enter__()
        self.conn.execute("SELECT set_config('app.current_org', %s, true)", (ACME,))
        self.enviados = []

    def tearDown(self):
        self.tx.__exit__(None, None, None)
        self.conn.close()

    def uno(self, sql, *params):
        return self.conn.execute(sql, params).fetchone()

    def enviar(self, codigo):
        def envio(url, mensaje):
            self.enviados.append((url, mensaje))
            return codigo
        return envio

    def test_1_un_critico_nuevo_deja_alerta_y_entrega_y_se_entrega_en_menos_de_60_s(self):
        teams = integracion(self.conn)
        apagada = integracion(self.conn, encendida=False)
        alertas = outbox.encolar_hallazgos(self.conn, ACME, DOMINIO, {CRITICO})
        self.assertEqual(len(alertas), 1)
        alerta = self.uno('SELECT event_type, finding_id::text, severity, payload FROM alerts WHERE id = %s', alertas[0])
        self.assertEqual((alerta['event_type'], alerta['finding_id'], alerta['severity']),
                         ('finding.created', CRITICO, 'critical'))
        self.assertEqual(alerta['payload']['domain'], 'acme-demo.mx')
        entregas = self.conn.execute('SELECT integration_id::text, status FROM deliveries WHERE alert_id = %s',
                                     (alertas[0],)).fetchall()
        self.assertEqual(entregas, [{'integration_id': teams, 'status': 'pending'}])   # la apagada no recibe
        self.assertNotIn(apagada, [e['integration_id'] for e in entregas])

        self.assertEqual(outbox.despachar(ACME, self.enviar(202), conn=self.conn), 1)
        self.assertEqual(self.enviados[0][0], URL)   # se descifró la URL completa, con su firma
        self.assertEqual(self.enviados[0][1]['attachments'][0]['contentType'],
                         'application/vnd.microsoft.card.adaptive')
        fila = self.uno('SELECT status, attempt, response_status, latency_ms, last_error FROM deliveries '
                        'WHERE alert_id = %s', alertas[0])
        self.assertEqual((fila['status'], fila['attempt'], fila['response_status'], fila['last_error']),
                         ('delivered', 1, 202, None))
        self.assertLess(fila['latency_ms'], 60000)
        self.assertEqual(outbox.despachar(ACME, self.enviar(202), conn=self.conn), 0)   # no se manda dos veces

    def test_2_lo_que_no_es_critico_o_no_esta_abierto_no_alerta(self):
        integracion(self.conn)
        no_critico = self.uno("SELECT id::text FROM findings WHERE domain_id = %s AND severity <> 'critical' "
                              "AND status = 'open' LIMIT 1", DOMINIO)['id']
        self.assertEqual(outbox.encolar_hallazgos(self.conn, ACME, DOMINIO, {no_critico}), [])
        self.assertEqual(outbox.encolar_hallazgos(self.conn, ACME, DOMINIO, set()), [])

    def test_3_reintenta_con_espera_y_al_quinto_fallo_queda_dead(self):
        integracion(self.conn)
        alerta = outbox.encolar_hallazgos(self.conn, ACME, DOMINIO, {CRITICO})[0]
        for intento in range(1, tarjeta.MAX_INTENTOS + 1):
            self.assertEqual(outbox.despachar(ACME, self.enviar(500), conn=self.conn), 1)
            fila = self.uno("SELECT status, attempt, response_status, last_error, "
                            "extract(epoch FROM next_attempt_at - now()) AS espera FROM deliveries WHERE alert_id = %s",
                            alerta)
            self.assertEqual((fila['attempt'], fila['response_status']), (intento, 500))
            self.assertIn('HTTP 500', fila['last_error'])
            if intento < tarjeta.MAX_INTENTOS:
                self.assertEqual(fila['status'], 'retrying')
                self.assertAlmostEqual(float(fila['espera']), tarjeta.espera(intento), delta=5)
                self.assertEqual(outbox.despachar(ACME, self.enviar(500), conn=self.conn), 0)   # todavía no toca
                self.conn.execute("UPDATE deliveries SET next_attempt_at = now() - interval '1 second' "
                                  "WHERE alert_id = %s", (alerta,))
            else:
                self.assertEqual((fila['status'], fila['espera']), ('dead', None))
        self.assertEqual(outbox.despachar(ACME, self.enviar(202), conn=self.conn), 0)   # una muerta ya no sale

    def test_4_una_url_que_no_abre_queda_como_error_sin_mostrarla(self):
        teams = integracion(self.conn)
        # La URL de otra integración no abre con este id (dato asociado del cifrado)
        self.conn.execute('UPDATE integrations SET secret_enc = %s WHERE id = %s',
                          (outbox.cifrar_url(str(uuid.uuid4()), URL), teams))
        alerta = outbox.encolar_hallazgos(self.conn, ACME, DOMINIO, {CRITICO})[0]
        outbox.despachar(ACME, self.enviar(202), conn=self.conn)
        fila = self.uno('SELECT status, last_error FROM deliveries WHERE alert_id = %s', alerta)
        self.assertEqual(fila['status'], 'retrying')
        self.assertIn('no abre', fila['last_error'])
        self.assertNotIn('CIRDAN_FAKE_firma', fila['last_error'])
        self.assertEqual(self.enviados, [])

    def test_5_el_score_alerta_solo_al_cruzar_el_umbral(self):
        integracion(self.conn)
        ultimo = self.uno('SELECT id::text, score FROM domain_scores WHERE domain_id = %s '
                          'ORDER BY computed_at DESC LIMIT 1', DOMINIO)
        anterior = self.uno('SELECT score FROM domain_scores WHERE domain_id = %s AND id <> %s '
                            'ORDER BY computed_at DESC LIMIT 1', DOMINIO, ultimo['id'])['score']
        # El anterior quedó abajo del umbral: el que llega a 95 cruza y alerta
        self.conn.execute('UPDATE organizations SET alert_score_threshold = %s WHERE id = %s', (anterior + 1, ACME))
        alerta = outbox.encolar_score(self.conn, ACME, DOMINIO, ultimo['id'], 95)
        fila = self.uno('SELECT event_type, score_id::text, severity, payload FROM alerts WHERE id = %s', alerta)
        self.assertEqual((fila['event_type'], fila['score_id'], fila['severity']),
                         ('score.above_threshold', ultimo['id'], 'critical'))
        self.assertEqual((fila['payload']['score'], fila['payload']['previous_score']), (95, anterior))
        self.assertEqual(self.uno('SELECT count(*) AS n FROM deliveries WHERE alert_id = %s', alerta)['n'], 1)
        # Abajo del umbral no alerta, y si el anterior ya estaba arriba tampoco (no se repite en cada escaneo)
        self.assertIsNone(outbox.encolar_score(self.conn, ACME, DOMINIO, ultimo['id'], anterior))
        self.conn.execute('UPDATE organizations SET alert_score_threshold = %s WHERE id = %s', (anterior, ACME))
        self.assertIsNone(outbox.encolar_score(self.conn, ACME, DOMINIO, ultimo['id'], 95))


if __name__ == '__main__':
    unittest.main()

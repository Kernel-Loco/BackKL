"""Pruebas sin base ni red del triage y las métricas de remediación (#80, RC-133).

    python -m unittest -v pruebas/test_triage.py

La ruta POST /api/v1/findings/{id}/triage y GET /domains/{fqdn}/remediation se prueban contra la base en
pruebas/test_api_v1.py (test_9t).
"""
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from cirdan import triage

HOY = date(2026, 11, 26)


def fila(estado, detectado=None, resuelto=None):
    return {'status': estado, 'detected_at': detectado, 'resolved_at': resuelto}


class Validar(unittest.TestCase):

    def test_1_falso_positivo_y_reabrir_sin_motivo_ni_fecha(self):
        for estado in ('false_positive', 'open'):
            with self.subTest(estado=estado):
                self.assertEqual(triage.validar({'status': estado}, 'spf_missing', HOY),
                                 {'status': estado, 'reason': None, 'review_date': None, 'note': None})

    def test_2_resuelto_por_omision_es_fixed_y_secreto_rotado_solo_en_secretos(self):
        self.assertEqual(triage.validar({'status': 'resolved'}, 'spf_missing', HOY)['reason'], 'fixed')
        self.assertEqual(triage.validar({'status': 'resolved', 'reason': 'secret_rotated'},
                                        'secret_in_public_repo', HOY)['reason'], 'secret_rotated')
        with self.assertRaisesRegex(ValueError, 'secret_rotated'):
            triage.validar({'status': 'resolved', 'reason': 'secret_rotated'}, 'spf_missing', HOY)
        with self.assertRaisesRegex(ValueError, 'reason debe ser'):
            triage.validar({'status': 'resolved', 'reason': 'porque si'}, 'spf_missing', HOY)
        with self.assertRaisesRegex(ValueError, 'solo va con status resolved'):
            triage.validar({'status': 'false_positive', 'reason': 'fixed'}, 'spf_missing', HOY)

    def test_3_riesgo_aceptado_pide_fecha_de_manana_a_un_ano(self):
        manana = HOY + timedelta(days=1)
        self.assertEqual(triage.validar({'status': 'accepted_risk', 'review_date': manana.isoformat()}, 'x', HOY)
                         ['review_date'], manana)
        for revision in (None, 'mañana', HOY.isoformat(), (HOY + timedelta(days=366)).isoformat(), 20261127):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                triage.validar({'status': 'accepted_risk', 'review_date': revision}, 'x', HOY)
        with self.assertRaisesRegex(ValueError, 'solo va con status accepted_risk'):
            triage.validar({'status': 'open', 'review_date': manana.isoformat()}, 'x', HOY)

    def test_4_estado_desconocido_campos_de_mas_y_nota_larga(self):
        for payload in ({'status': 'borrado'}, {}, [], {'status': 'open', 'severity': 'low'},
                        {'status': 'open', 'note': 'x' * 501}, {'status': 'open', 'note': 5}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                triage.validar(payload, 'x', HOY)

    def test_5_la_nota_quita_caracteres_de_control_y_espacios(self):
        self.assertEqual(triage.validar({'status': 'open', 'note': '  revisado\x00 con TI \n'}, 'x', HOY)['note'],
                         'revisado con TI')
        self.assertIsNone(triage.validar({'status': 'open', 'note': '   '}, 'x', HOY)['note'])


class Detalles(unittest.TestCase):

    def test_1_el_evento_lleva_antes_despues_y_lo_que_dijo_el_cliente(self):
        cambio = triage.validar({'status': 'accepted_risk', 'review_date': '2027-01-15', 'note': 'Lo ve TI'}, 'x', HOY)
        self.assertEqual(triage.detalles('open', cambio),
                         {'from': 'open', 'to': 'accepted_risk', 'review_date': '2027-01-15', 'note': 'Lo ve TI'})

    def test_2_resuelto_usa_la_accion_que_lee_el_orquestador(self):
        # Se lee el texto: importar el orquestador pide psycopg, que este paso del CI no trae.
        fuente = (Path(__file__).resolve().parents[1] / 'cirdan' / 'orquestador' / '__init__.py').read_text('utf-8')
        self.assertIn("ACCION_HALLAZGO_RESUELTO = '%s'" % triage.ACCIONES['resolved'], fuente)
        self.assertIn("MOTIVO_SECRETO_ROTADO = '%s'" % triage.MOTIVO_SECRETO_ROTADO, fuente)
        self.assertEqual(set(triage.ACCIONES), set(triage.ESTADOS))


class RevisionVencida(unittest.TestCase):

    def test_1_el_riesgo_aceptado_vuelve_al_plan_el_dia_de_su_revision(self):
        self.assertFalse(triage.revision_vencida('accepted_risk', '2026-11-27', HOY))
        self.assertTrue(triage.revision_vencida('accepted_risk', '2026-11-26', HOY))
        self.assertTrue(triage.revision_vencida('accepted_risk', date(2026, 1, 1), HOY))

    def test_2_sin_fecha_o_con_fecha_rota_vuelve_y_otros_estados_no(self):
        self.assertTrue(triage.revision_vencida('accepted_risk', None, HOY))
        self.assertTrue(triage.revision_vencida('accepted_risk', 'no-fecha', HOY))
        self.assertFalse(triage.revision_vencida('open', None, HOY))
        self.assertFalse(triage.revision_vencida('false_positive', None, HOY))


class Metricas(unittest.TestCase):

    def test_1_tiempo_medio_y_porcentaje_sin_falsos_positivos(self):
        t = datetime(2026, 11, 1, tzinfo=timezone.utc)
        filas = [fila('resolved', t, t + timedelta(days=2)), fila('resolved', t, t + timedelta(days=4)),
                 fila('open', t), fila('accepted_risk', t), fila('false_positive', t)]
        m = triage.metricas(filas)
        self.assertEqual(m['total'], 5)
        self.assertEqual(m['by_status'], {'open': 1, 'resolved': 2, 'accepted_risk': 1, 'false_positive': 1})
        self.assertEqual((m['closed'], m['closed_pct']), (2, 50.0))
        self.assertEqual((m['mean_time_to_remediate_days'], m['remediated_count']), (3.0, 2))

    def test_2_sin_hallazgos_o_sin_resueltos_da_null(self):
        self.assertEqual((triage.metricas([])['closed_pct'], triage.metricas([])['mean_time_to_remediate_days']),
                         (None, None))
        solo_fp = triage.metricas([fila('false_positive')])
        self.assertEqual((solo_fp['closed_pct'], solo_fp['total']), (None, 1))
        self.assertEqual(triage.metricas([fila('open')])['closed_pct'], 0.0)

    def test_3_un_reabierto_no_cuenta_como_remediado(self):
        # El orquestador lo devuelve a open y limpia resolved_at: no entra al promedio ni a los cerrados.
        t = datetime(2026, 11, 1, tzinfo=timezone.utc)
        m = triage.metricas([fila('open', t, None), fila('resolved', t, t + timedelta(hours=12))])
        self.assertEqual((m['closed'], m['closed_pct'], m['mean_time_to_remediate_days']), (1, 50.0, 0.5))


if __name__ == '__main__':
    unittest.main()

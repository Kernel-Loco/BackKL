"""Pruebas de comparación semanal con dos escaneos de ejemplo."""
import unittest
from datetime import datetime, timedelta, timezone

from cirdan.score.cambios import resumen_semanal


AHORA = datetime(2026, 11, 13, 12, tzinfo=timezone.utc)


class CambiosSemanales(unittest.TestCase):

    def setUp(self):
        self.anterior = {
            'scan_id': 'scan-previous',
            'finished_at': AHORA - timedelta(days=6),
            'stats': {'assets': 10},
        }

    def actual(self, assets=13, new_assets=1, new_findings=1, finished_at=AHORA):
        return {
            'scan_id': 'scan-current',
            'finished_at': finished_at,
            'stats': {'assets': assets, 'new_findings': new_findings},
            'new_assets': new_assets,
        }

    def test_detecta_activos_hallazgos_nuevos_y_crecimiento_mayor_a_20_por_ciento(self):
        changes = resumen_semanal(self.actual(), [self.anterior])
        self.assertEqual(changes['previous_scan_id'], 'scan-previous')
        self.assertEqual(changes['assets_growth_percent'], 30)
        self.assertEqual(changes['new_assets'], 1)
        self.assertEqual(changes['new_findings'], 1)
        self.assertEqual(changes['alerts'], {
            'new_asset': True,
            'new_finding': True,
            'assets_growth_over_20_percent': True,
        })

    def test_un_crecimiento_de_exactamente_20_por_ciento_no_dispara_alerta(self):
        changes = resumen_semanal(self.actual(assets=12, new_assets=0, new_findings=0), [self.anterior])
        self.assertIsNone(changes)

    def test_compara_hallazgo_nuevo_aunque_el_escaneo_anterior_pase_del_tope_de_14_dias(self):
        old_scan = {**self.anterior, 'finished_at': AHORA - timedelta(days=14, minutes=1)}
        changes = resumen_semanal(self.actual(assets=13, new_assets=0, new_findings=1), [old_scan])
        self.assertEqual(changes['alerts']['new_finding'], True)
        self.assertEqual(changes['previous_scan_id'], 'scan-previous')
        self.assertIsNone(changes['assets_before'])
        self.assertIsNone(changes['assets_growth_percent'])
        self.assertFalse(changes['alerts']['assets_growth_over_20_percent'])

    def test_sin_novedades_no_agrega_resumen_al_historico(self):
        self.assertIsNone(resumen_semanal(self.actual(assets=10, new_assets=0, new_findings=0), [self.anterior]))

    def test_programador_semanal_corrido_unos_minutos_si_mide_la_semana(self):
        # Una semana y 5 minutos: ningún escaneo cae en los 7 días, así que cuenta el respaldo de 14 días.
        semana_y_minutos = {**self.anterior, 'finished_at': AHORA - timedelta(days=7, minutes=5)}
        changes = resumen_semanal(self.actual(assets=13, new_assets=0, new_findings=0), [semana_y_minutos])
        self.assertEqual(changes['assets_growth_percent'], 30)
        self.assertTrue(changes['alerts']['assets_growth_over_20_percent'])
        self.assertEqual(changes['previous_scan_id'], 'scan-previous')
        self.assertEqual(changes['assets_before'], 10)

    def test_varios_escaneos_de_la_semana_con_menos_de_20_cada_uno_si_suman(self):
        # 10 -> 11 -> 12 -> 13: cada paso es menos de 20 %, la semana es +30 %.
        escaneos = [
            {'scan_id': 'scan-d6', 'finished_at': AHORA - timedelta(days=6), 'stats': {'assets': 10}},
            {'scan_id': 'scan-d4', 'finished_at': AHORA - timedelta(days=4), 'stats': {'assets': 11}},
            {'scan_id': 'scan-d2', 'finished_at': AHORA - timedelta(days=2), 'stats': {'assets': 12}},
        ]
        changes = resumen_semanal(self.actual(assets=13, new_assets=0, new_findings=0), escaneos)
        self.assertEqual(changes['previous_scan_id'], 'scan-d6')
        self.assertEqual(changes['assets_before'], 10)
        self.assertEqual(changes['assets_growth_percent'], 30)
        self.assertTrue(changes['alerts']['assets_growth_over_20_percent'])

    def test_la_base_es_el_mas_viejo_dentro_de_la_semana_no_uno_de_antes(self):
        escaneos = [
            {'scan_id': 'scan-d10', 'finished_at': AHORA - timedelta(days=10), 'stats': {'assets': 5}},
            {'scan_id': 'scan-d3', 'finished_at': AHORA - timedelta(days=3), 'stats': {'assets': 11}},
        ]
        changes = resumen_semanal(self.actual(assets=13, new_assets=0, new_findings=1), escaneos)
        self.assertEqual(changes['previous_scan_id'], 'scan-d3')
        self.assertEqual(changes['assets_growth_percent'], 18.18)
        self.assertFalse(changes['alerts']['assets_growth_over_20_percent'])

    def test_sin_escaneo_anterior_no_calcula_crecimiento(self):
        changes = resumen_semanal(self.actual(assets=13, new_assets=13, new_findings=0), [])
        self.assertIsNone(changes['previous_scan_id'])
        self.assertIsNone(changes['assets_growth_percent'])
        self.assertTrue(changes['alerts']['new_asset'])


    def test_un_escaneo_fallido_o_sin_activos_no_sirve_de_base(self):
        # El fallido de hace 6 días guarda 0 activos y uno sin stats no los contó: la base es el de hace 4 días.
        escaneos = [
            {'scan_id': 'scan-fallido', 'scan_status': 'failed', 'finished_at': AHORA - timedelta(days=6),
             'stats': {'assets': 0}},
            {'scan_id': 'scan-sin-stats', 'scan_status': 'completed', 'finished_at': AHORA - timedelta(days=5),
             'stats': None},
            {'scan_id': 'scan-d4', 'scan_status': 'partial', 'finished_at': AHORA - timedelta(days=4),
             'stats': {'assets': 10}},
        ]
        changes = resumen_semanal(self.actual(assets=13, new_assets=0, new_findings=0), escaneos)
        self.assertEqual(changes['previous_scan_id'], 'scan-d4')
        self.assertEqual(changes['assets_before'], 10)
        self.assertEqual(changes['assets_growth_percent'], 30)

    def test_solo_un_fallido_antes_no_calcula_crecimiento(self):
        fallido = {'scan_id': 'scan-fallido', 'scan_status': 'failed', 'finished_at': AHORA - timedelta(days=2),
                   'stats': {'assets': 4}}
        changes = resumen_semanal(self.actual(assets=13, new_assets=1, new_findings=0), [fallido])
        self.assertEqual(changes['previous_scan_id'], 'scan-fallido')  # referencia, no base
        self.assertIsNone(changes['assets_before'])
        self.assertIsNone(changes['assets_growth_percent'])

    def test_apenas_mas_de_20_por_ciento_si_dispara_aunque_redondee_a_20(self):
        base = {**self.anterior, 'stats': {'assets': 100000}}
        changes = resumen_semanal(self.actual(assets=120001, new_assets=0, new_findings=0), [base])
        self.assertEqual(changes['assets_growth_percent'], 20.0)
        self.assertTrue(changes['alerts']['assets_growth_over_20_percent'])


if __name__ == '__main__':
    unittest.main(verbosity=2)

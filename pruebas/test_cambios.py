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
        changes = resumen_semanal(self.actual(), self.anterior)
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
        changes = resumen_semanal(self.actual(assets=12, new_assets=0, new_findings=0), self.anterior)
        self.assertIsNone(changes)

    def test_compara_hallazgo_nuevo_aunque_el_escaneo_anterior_tenga_mas_de_una_semana(self):
        old_scan = {**self.anterior, 'finished_at': AHORA - timedelta(days=8)}
        changes = resumen_semanal(self.actual(assets=12, new_assets=0, new_findings=1), old_scan)
        self.assertEqual(changes['alerts']['new_finding'], True)
        self.assertIsNone(changes['assets_growth_percent'])
        self.assertFalse(changes['alerts']['assets_growth_over_20_percent'])

    def test_sin_novedades_no_agrega_resumen_al_historico(self):
        self.assertIsNone(resumen_semanal(self.actual(assets=10, new_assets=0, new_findings=0), self.anterior))


if __name__ == '__main__':
    unittest.main(verbosity=2)

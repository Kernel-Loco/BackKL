"""Pruebas sin base ni red de las exportaciones y la comparación de #24 (RC-57).

    python -m unittest -v pruebas/test_exportar.py
"""
import csv
import io
import unittest
from datetime import datetime, timezone
from decimal import Decimal

from cirdan import exportar
from cirdan.score import comparacion, plan


def aporte(finding_id, severity, penalty, status='open', rule_code='spf_missing', asset='acme.mx'):
    return {'finding_id': finding_id, 'severity': severity, 'penalty': Decimal(penalty), 'title': 'T ' + finding_id,
            'rule_code': rule_code, 'category': 'digital_identity', 'asset': asset, 'asset_type': 'domain',
            'status': status}


def leer_csv(texto):
    return list(csv.reader(io.StringIO(texto.removeprefix('﻿'), newline='')))


class Escape(unittest.TestCase):

    def test_1_cada_inicio_de_formula_lleva_comilla(self):
        for inicio in ('=', '+', '-', '@', '\t', '\r'):
            self.assertEqual(exportar.escapar_formula(inicio + 'SUM(A1)'), "'" + inicio + 'SUM(A1)', repr(inicio))

    def test_2_texto_normal_y_numeros_no_cambian(self):
        for valor in ('acme.mx', ' =no empieza con signo', 'a=b', '', 'año'):
            self.assertEqual(exportar.escapar_formula(valor), valor)
        self.assertEqual(exportar.celda(-5), '-5')
        self.assertEqual(exportar.celda(Decimal('-2.50')), '-2.50')
        self.assertEqual(exportar.celda(None), '')
        self.assertEqual(exportar.celda(True), 'true')

    def test_3_listas_y_diccionarios_se_recorren(self):
        self.assertEqual(exportar.escapar_formula({'a': ['=1', 'x'], 'b': {'c': '@d'}}),
                         {'a': ["'=1", 'x'], 'b': {'c': "'@d"}})

    def test_4_csv_con_bom_crlf_y_celdas_escapadas(self):
        fecha = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
        texto = exportar.csv_con_bom(('titulo', 'fecha', 'evidencia', 'n'),
                                     [('=HYPERLINK("http://x","clic")', fecha, {'banner': '-cmd'}, -3),
                                      ('\tTab, con coma', None, [], 0)])
        self.assertTrue(texto.startswith('﻿'))
        self.assertIn('\r\n', texto)
        filas = leer_csv(texto)
        self.assertEqual(filas[0], ['titulo', 'fecha', 'evidencia', 'n'])
        self.assertEqual(filas[1], ['\'=HYPERLINK("http://x","clic")', '2026-11-07T12:00:00+00:00',
                                    '{"banner": "-cmd"}', '-3'])
        self.assertEqual(filas[2], ["'\tTab, con coma", '', '[]', '0'])

    def test_5_el_plan_usa_el_mismo_escape(self):
        self.assertIs(plan.escapar_formula, exportar.escapar_formula)
        self.assertEqual(plan.escapar_formula('\rx'), "'\rx")


class Comparacion(unittest.TestCase):

    def test_1_nuevo_ya_no_esta_y_sigue(self):
        items, resumen = comparacion.comparar(
            [aporte('a', 'high', '20'), aporte('b', 'low', '8', status='resolved'), aporte('c', 'medium', '10')],
            [aporte('a', 'critical', '40'), aporte('c', 'medium', '10'), aporte('d', 'low', '8')])
        self.assertEqual([(i['finding_id'], i['change'], i['severity_changed']) for i in items],
                         [('d', 'new', False), ('b', 'gone', False), ('a', 'kept', True), ('c', 'kept', False)])
        self.assertEqual(resumen, {'new': 1, 'gone': 1, 'kept': 2, 'severity_changed': 1})
        a = next(i for i in items if i['finding_id'] == 'a')
        self.assertEqual((a['severity_from'], a['severity_to'], a['penalty_from'], a['penalty_to']),
                         ('high', 'critical', 20.0, 40.0))
        b = next(i for i in items if i['finding_id'] == 'b')
        self.assertEqual((b['severity_to'], b['penalty_to'], b['status_now']), (None, None, 'resolved'))

    def test_2_el_mismo_score_contra_si_mismo_no_tiene_cambios(self):
        fotos = [aporte('a', 'high', '20'), aporte('b', 'low', '8')]
        items, resumen = comparacion.comparar(fotos, fotos)
        self.assertEqual(resumen, {'new': 0, 'gone': 0, 'kept': 2, 'severity_changed': 0})
        self.assertEqual(len(items), 2)

    def test_3_sin_aportes_da_lista_vacia(self):
        self.assertEqual(comparacion.comparar([], []), ([], {'new': 0, 'gone': 0, 'kept': 0, 'severity_changed': 0}))

    def test_4_csv_de_la_comparacion_escapa_y_trae_un_renglon_por_hallazgo(self):
        items, resumen = comparacion.comparar([], [aporte('x', 'high', '20', asset='=cmd|calc')])
        data = {'domain': 'acme.mx', 'summary': resumen, 'items': items, 'total': len(items),
                'from': {'score_id': 's1', 'computed_at': datetime(2026, 10, 1, tzinfo=timezone.utc)},
                'to': {'score_id': 's2', 'computed_at': datetime(2026, 11, 1, tzinfo=timezone.utc)}}
        filas = leer_csv(comparacion.exportar_csv(data))
        self.assertEqual(filas[0], list(comparacion.ENCABEZADOS_CSV))
        self.assertEqual(len(filas), 2)
        fila = dict(zip(filas[0], filas[1]))
        self.assertEqual((fila['cambio'], fila['activo'], fila['severidad_desde'], fila['puntos_hasta']),
                         ('new', "'=cmd|calc", '', '20.0'))


if __name__ == '__main__':
    unittest.main(verbosity=2)

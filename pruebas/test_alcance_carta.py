"""Alcance de la carta (RC-59): actividades del Anexo A, fuentes y la regla de la base, sin base ni red."""
import re
import unittest
from pathlib import Path

from cirdan import alcance_carta
from cirdan.recolectores import REGISTRO

RAIZ = Path(__file__).resolve().parent.parent
MIGRACION = RAIZ / 'db' / 'migraciones' / '029_alcance_carta_y_otra_empresa.sql'
SEMILLA = RAIZ / 'db' / 'semillas' / '027_alcance_cartas.sql'
PLANTILLA = RAIZ / 'docs' / 'plantilla_carta_autorizacion.md'


def arreglos(texto):
    return [sorted(int(n) for n in m.split(',')) for m in re.findall(r'ARRAY\[([\d,\s]+)\]', texto)]


class AlcanceCarta(unittest.TestCase):
    def test_cada_fuente_tiene_su_actividad(self):
        self.assertEqual(set(REGISTRO) - set(alcance_carta.ACTIVIDAD_DE_FUENTE), {alcance_carta.FUENTE_PRUEBAS})
        vigente = alcance_carta.PLANTILLAS[alcance_carta.PLANTILLA_VIGENTE]
        self.assertLessEqual(set(alcance_carta.ACTIVIDAD_DE_FUENTE.values()), vigente)

    def test_las_actividades_son_las_del_anexo_a_de_la_plantilla(self):
        anexo = PLANTILLA.read_text(encoding='utf-8').split('## Anexo A', 1)[1]
        filas = {int(n) for n in re.findall(r'^\| (\d+) \|', anexo, re.M)}
        self.assertEqual(filas, alcance_carta.PLANTILLAS[alcance_carta.PLANTILLA_VIGENTE])

    def test_la_base_acepta_lo_mismo_que_el_codigo(self):
        migracion = MIGRACION.read_text(encoding='utf-8')
        todas = sorted(alcance_carta.PLANTILLAS[1])
        # el CHECK de las actividades y el llenado de las cartas viejas, en la migración y en la semilla
        self.assertEqual(arreglos(migracion), [todas, todas])
        self.assertEqual(arreglos(SEMILLA.read_text(encoding='utf-8')), [todas])
        versiones = re.search(r'template_version IS NULL OR template_version = (\d+)\)', migracion).group(1)
        self.assertEqual({int(versiones)}, set(alcance_carta.PLANTILLAS))

    def test_actividades_validas(self):
        self.assertEqual(alcance_carta.actividades_validas(1, [3, 1, 2]), [1, 2, 3])
        self.assertEqual(alcance_carta.actividades_validas(1, list(range(1, 12))), list(range(1, 12)))
        for version, actividades in ((2, [1]), ('1', [1]), (True, [1]), (None, [1]), (1, []), (1, None), (1, [0]),
                                     (1, [12]), (1, [1, 1]), (1, ['1']), (1, [True]), (1, [1.0]), (1, {1: 1})):
            with self.subTest(version=version, actividades=actividades):
                self.assertIsNone(alcance_carta.actividades_validas(version, actividades))

    def test_autorizada(self):
        self.assertTrue(alcance_carta.autorizada('dns', [2]))
        self.assertFalse(alcance_carta.autorizada('ct_logs', [2]))
        self.assertFalse(alcance_carta.autorizada('subfinder', [2]))
        self.assertFalse(alcance_carta.autorizada('dns', None))   # carta sin alcance: nada
        self.assertFalse(alcance_carta.autorizada('desconocida', list(range(1, 12))))
        self.assertTrue(alcance_carta.autorizada(alcance_carta.FUENTE_PRUEBAS, None))


if __name__ == '__main__':
    unittest.main()

"""Reglas del cambio de rol y de la baja de cuentas (#141, RC-259), sin base ni red.

    python -m unittest -v pruebas/test_cuentas.py

Las rutas se prueban contra la base en pruebas/test_usuarios_admin.py.
"""
import unittest

from cirdan.auth import cuentas

ALEX, JORDAN, MAYA, OTRO = 'a', 'j', 'm', 'o'


def cuenta(id_, rol='analyst', activo=True):
    return {'id': id_, 'role': rol, 'is_active': activo}


class ValidarCambio(unittest.TestCase):

    def test_1_el_admin_cambia_el_rol_y_desactiva_a_otro(self):
        self.assertEqual(cuentas.validar_cambio(ALEX, cuenta(JORDAN), rol='manager', admins_activos=[ALEX]),
                         {'role': 'manager', 'is_active': None})
        self.assertEqual(cuentas.validar_cambio(ALEX, cuenta(JORDAN), activo=False, admins_activos=[ALEX]),
                         {'role': None, 'is_active': False})
        self.assertEqual(cuentas.validar_cambio(ALEX, cuenta(JORDAN, activo=False), activo=True, admins_activos=[ALEX]),
                         {'role': None, 'is_active': True})

    def test_2_pedir_lo_mismo_no_cambia_nada(self):
        self.assertEqual(cuentas.validar_cambio(ALEX, cuenta(JORDAN), rol='analyst', activo=True, admins_activos=[ALEX]),
                         {'role': None, 'is_active': None})

    def test_3_nadie_se_quita_su_rol_ni_se_desactiva(self):
        for cambio in ({'rol': 'analyst'}, {'activo': False}):
            with self.subTest(cambio=cambio), self.assertRaisesRegex(cuentas.CambioInvalido, 'propio rol'):
                cuentas.validar_cambio(ALEX, cuenta(ALEX, 'admin'), admins_activos=[ALEX, MAYA], **cambio)
        # Confirmar el propio rol de admin sin cambiarlo sí se puede (no hace nada)
        self.assertEqual(cuentas.validar_cambio(ALEX, cuenta(ALEX, 'admin'), rol='admin', admins_activos=[ALEX]),
                         {'role': None, 'is_active': None})

    def test_4_no_se_queda_la_empresa_sin_admin_activo(self):
        # Un superadmin de la plataforma (otro actor) intenta quitar al único Admin
        for cambio in ({'rol': 'manager'}, {'activo': False}):
            with self.subTest(cambio=cambio), self.assertRaisesRegex(cuentas.CambioInvalido, 'último Admin'):
                cuentas.validar_cambio(OTRO, cuenta(ALEX, 'admin'), admins_activos=[ALEX], **cambio)
        # Con otro Admin activo sí se puede
        self.assertEqual(cuentas.validar_cambio(MAYA, cuenta(ALEX, 'admin'), rol='manager', admins_activos=[ALEX, MAYA]),
                         {'role': 'manager', 'is_active': None})
        # Un Admin ya inactivo no cuenta como el último
        self.assertEqual(cuentas.validar_cambio(OTRO, cuenta(MAYA, 'admin', activo=False), rol='analyst',
                                                admins_activos=[ALEX]), {'role': 'analyst', 'is_active': None})

    def test_5_el_rol_de_integrador_no_se_toca_aqui(self):
        with self.assertRaisesRegex(cuentas.CambioInvalido, 'operator'):
            cuentas.validar_cambio(ALEX, cuenta(OTRO, 'operator'), activo=False, admins_activos=[ALEX])
        with self.assertRaises(cuentas.CambioInvalido) as error:
            cuentas.validar_cambio(ALEX, cuenta(JORDAN), rol='operator', admins_activos=[ALEX])
        self.assertEqual(error.exception.codigo, 422)

    def test_6_cuerpo_invalido_es_422(self):
        for kwargs in ({}, {'activo': 'false'}, {'rol': 'superadmin'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(cuentas.CambioInvalido) as error:
                cuentas.validar_cambio(ALEX, cuenta(JORDAN), admins_activos=[ALEX], **kwargs)
            self.assertEqual(error.exception.codigo, 422)


class Motivo(unittest.TestCase):

    def test_1_el_motivo_es_obligatorio_y_se_limpia(self):
        self.assertEqual(cuentas.motivo_valido('  Cambió   de área\x00 '), 'Cambió de área')
        for motivo in (None, '', 'ok', 'x' * 301, 5):
            with self.subTest(motivo=motivo), self.assertRaises(cuentas.CambioInvalido) as error:
                cuentas.motivo_valido(motivo)
            self.assertEqual(error.exception.codigo, 422)


if __name__ == '__main__':
    unittest.main()

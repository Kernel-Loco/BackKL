"""Pruebas sin red del captcha del login (cirdan/auth/captcha.py, RC-154). Valkey se reemplaza por un diccionario.

Necesitan la librería altcha, que trae la imagen de la API:
    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest pruebas/test_captcha.py
"""
import base64
import hashlib
import json
import struct
import time
import unittest
from unittest import mock

import altcha

from cirdan.auth import captcha
from pruebas.sesion import solve_captcha

LLAVE = 'llave-de-prueba-del-captcha'


class Verify(unittest.TestCase):

    def setUp(self):
        self.usados = {}  # nonce -> segundos que se guardaría en Valkey

        def gastar(nonce, seconds):  # como SET NX EX
            self.assertGreater(seconds, 0)
            if nonce in self.usados:
                return False
            self.usados[nonce] = seconds
            return True

        for nombre, falso in (('captcha_hmac_key', lambda candidate: LLAVE), ('spend_captcha', gastar)):
            parche = mock.patch.object(captcha.sessions, nombre, side_effect=falso)
            parche.start()
            self.addCleanup(parche.stop)

    def _firmado(self, **cambios):
        """Un reto firmado con la llave de la API, con otros parámetros."""
        opciones = dict(algorithm=captcha.ALGORITHM, cost=50, key_prefix='0', expires_at=int(time.time()) + 60,
                        hmac_secret=LLAVE)
        opciones.update(cambios)
        return altcha.create_challenge(opciones.pop('algorithm'), opciones.pop('cost'), **opciones).to_dict()

    def test_un_reto_de_la_api_resuelto_sirve_una_sola_vez(self):
        resuelto = solve_captcha(captcha.new_challenge())
        self.assertTrue(captcha.verify(resuelto))
        self.assertFalse(captcha.verify(resuelto), 'el segundo uso')

    def test_se_gasta_hasta_que_vence(self):
        reto = captcha.new_challenge()
        captcha.verify(solve_captcha(reto))
        segundos = self.usados[reto['parameters']['nonce']]
        self.assertAlmostEqual(segundos, captcha.CHALLENGE_SECONDS, delta=5)

    def test_vencido_no_sirve(self):
        self.assertFalse(captcha.verify(solve_captcha(self._firmado(expires_at=int(time.time()) - 1))))

    def test_sin_vencimiento_no_sirve_aunque_lo_firme_la_api(self):
        self.assertFalse(captcha.verify(solve_captcha(self._firmado(expires_at=None))))

    def test_otro_algoritmo_no_sirve_aunque_lo_firme_la_api(self):
        reto = self._firmado(algorithm='PBKDF2/SHA-512')
        self.assertFalse(captcha.verify(solve_captcha_sha512(reto)))

    def test_firmado_con_otra_llave_no_sirve(self):
        self.assertFalse(captcha.verify(solve_captcha(self._firmado(hmac_secret='otra-llave'))))

    def test_lo_que_no_se_lee_no_truena(self):
        for basura in (None, 123, '', '!!!', 'e30=', 'W10=', 'bnVsbA==', 'A' * (captcha.MAX_PAYLOAD + 1)):
            with self.subTest(basura=basura):
                self.assertFalse(captcha.verify(basura))
        self.assertEqual(self.usados, {}, 'nada de eso debe gastar un reto')

    def test_el_reto_cuesta_lo_que_dice_el_modulo(self):
        params = captcha.new_challenge()['parameters']
        self.assertEqual((params['algorithm'], params['cost'], params['keyPrefix']),
                         (captcha.ALGORITHM, captcha.COST, captcha.KEY_PREFIX))


def solve_captcha_sha512(challenge):
    """Como sesion.solve_captcha, con PBKDF2-SHA512."""
    params = challenge['parameters']
    nonce, salt = bytes.fromhex(params['nonce']), bytes.fromhex(params['salt'])
    counter = 0
    while True:
        key = hashlib.pbkdf2_hmac('sha512', nonce + struct.pack('>I', counter), salt, params['cost'], params['keyLength'])
        if key.hex().startswith(params['keyPrefix']):
            break
        counter += 1
    payload = {'challenge': {'parameters': params, 'signature': challenge['signature']},
               'solution': {'counter': counter, 'derivedKey': key.hex()}}
    return base64.b64encode(json.dumps(payload).encode()).decode()


if __name__ == '__main__':
    unittest.main(verbosity=2)

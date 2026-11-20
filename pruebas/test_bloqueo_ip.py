"""Pruebas del bloqueo por IP del login (cirdan/auth/sessions.py): una IPv6 cuenta por su red /64 (#49, RC-91).

Sin red y sin Valkey: el Valkey es falso. Corren dentro del contenedor, porque cirdan.auth.sessions importa redis:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_bloqueo_ip.py
"""
import unittest
from unittest import mock

from cirdan.auth import sessions


class ValkeyFalso:
    """Lo que usa el bloqueo por intentos: incr, expire, get, mget y pipeline."""

    def __init__(self):
        self.datos = {}

    def incr(self, llave):
        self.datos[llave] = self.datos.get(llave, 0) + 1
        return self.datos[llave]

    def expire(self, llave, segundos, nx=False):
        return True

    def get(self, llave):
        return self.datos.get(llave)

    def mget(self, *llaves):
        return [self.datos.get(llave) for llave in llaves]

    def pipeline(self):
        valkey, resultados = self, []

        class Tubo:
            def incr(self, llave):
                resultados.append(valkey.incr(llave))

            def expire(self, llave, segundos, nx=False):
                resultados.append(valkey.expire(llave, segundos, nx))

            def execute(self):
                return list(resultados)

        return Tubo()


class BloqueDeLaIp(unittest.TestCase):
    def test_1_una_ipv6_cuenta_por_su_red_64(self):
        self.assertEqual(sessions._ip_key('2001:db8:1:2:aaaa::1'), 'login:fail:ip:2001:db8:1:2::/64')
        self.assertEqual(sessions._ip_key('2001:DB8:1:2:ffff:ffff:ffff:ffff'), 'login:fail:ip:2001:db8:1:2::/64')
        self.assertNotEqual(sessions._ip_key('2001:db8:1:2::1'), sessions._ip_key('2001:db8:1:3::1'))

    def test_2_una_ipv4_cuenta_sola_aunque_venga_escrita_como_ipv6(self):
        self.assertEqual(sessions._ip_key('203.0.113.7'), 'login:fail:ip:203.0.113.7')
        self.assertEqual(sessions._ip_key('::ffff:203.0.113.7'), 'login:fail:ip:203.0.113.7')
        self.assertNotEqual(sessions._ip_key('203.0.113.7'), sessions._ip_key('203.0.113.8'))

    def test_3_lo_que_no_es_ip_queda_como_antes(self):
        self.assertEqual(sessions._ip_key(None), 'login:fail:ip:desconocida')
        self.assertEqual(sessions._ip_key(''), 'login:fail:ip:desconocida')
        self.assertEqual(sessions._ip_key('testclient'), 'login:fail:ip:testclient')

    def test_4_una_ipv6_con_zona_no_truena(self):
        self.assertEqual(sessions._ip_key('fe80::1%eth0'), 'login:fail:ip:fe80::/64')


class Rociado(unittest.TestCase):
    def setUp(self):
        self.valkey = ValkeyFalso()
        parche = mock.patch.object(sessions, '_valkey', lambda: self.valkey)
        parche.start()
        self.addCleanup(parche.stop)

    def test_5_estrenar_direccion_en_la_misma_64_no_salta_el_bloqueo(self):
        # Un correo distinto en cada intento, para que solo cuente el límite por IP.
        for n in range(sessions.MAX_FAILS_IP):
            sessions.register_fail('nadie%d@ejemplo.test' % n, '2001:db8:1:2::%x' % (n + 1))
        self.assertTrue(sessions.is_locked('otro@ejemplo.test', '2001:db8:1:2:dead:beef::1'))
        self.assertFalse(sessions.is_locked('otro@ejemplo.test', '2001:db8:1:3::1'))

    def test_6_el_codigo_equivocado_tambien_cuenta_por_la_64(self):
        for n in range(sessions.MAX_FAILS_IP):
            sessions.register_mfa_fail('2001:db8:9:9::%x' % (n + 1))
        self.assertFalse(sessions.take_mfa_attempt('otro@ejemplo.test', '2001:db8:9:9::ffff'))


if __name__ == '__main__':
    unittest.main()

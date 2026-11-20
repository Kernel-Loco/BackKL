"""Pruebas de la IP del cliente del login y de los orígenes permitidos (RC-277), sin red ni Valkey.

La IP con que el login cuenta sus 20 fallos la da uvicorn con --proxy-headers (Dockerfile): de derecha a izquierda,
la primera de X-Forwarded-For que no está en FORWARDED_ALLOW_IPS. Estas pruebas usan el ProxyHeadersMiddleware real de
uvicorn con la lista del despliegue (docker-compose.despliegue.yml, la revisa test_despliegue.py test_7) y con la del
README fuera de Docker (--forwarded-allow-ips=""), y el bloqueo real con un Valkey falso. Corren dentro del contenedor,
porque piden uvicorn y redis:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_ip_cliente.py
"""
import asyncio
import os
import unittest
from unittest import mock

from uvicorn.config import Config
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from cirdan import config as cfg
from cirdan.auth import sessions
from pruebas.test_bloqueo_ip import ValkeyFalso

# Las IP fijas del portal y de cloudflared en docker-compose.despliegue.yml.
DESPLIEGUE = '10.249.91.10,10.249.92.11'
PORTAL, TUNEL = DESPLIEGUE.split(',')


def ip_vista(confianza, de_quien, xff=None):
    """La IP que ve la API cuando `de_quien` le conecta con ese X-Forwarded-For y uvicorn confía en `confianza`."""
    vista = {}

    async def app(scope, receive, send):
        vista['ip'] = scope['client'][0]

    headers = [(b'x-forwarded-for', xff.encode())] if xff is not None else []
    scope = {'type': 'http', 'scheme': 'http', 'client': (de_quien, 50000), 'headers': headers}
    asyncio.run(ProxyHeadersMiddleware(app, trusted_hosts=confianza)(scope, None, None))
    return vista['ip']


class CadenaDelDespliegue(unittest.TestCase):
    def test_1_la_ip_inventada_por_el_navegador_no_cuenta(self):
        # Cloudflare agrega la IP real al final; el navegador puso la suya a la izquierda; Next no toca el encabezado.
        self.assertEqual(ip_vista(DESPLIEGUE, PORTAL, '6.6.6.6, 198.51.100.7'), '198.51.100.7')

    def test_2_tampoco_si_cloudflared_agrega_la_suya(self):
        self.assertEqual(ip_vista(DESPLIEGUE, PORTAL, '6.6.6.6, 198.51.100.7, ' + TUNEL), '198.51.100.7')

    def test_3_alguien_fuera_de_la_lista_no_elige_su_ip(self):
        self.assertEqual(ip_vista(DESPLIEGUE, '10.249.92.12', '6.6.6.6'), '10.249.92.12')

    def test_4_veinte_fallos_de_una_ip_no_bloquean_otra(self):
        valkey = ValkeyFalso()
        with mock.patch.object(sessions, '_valkey', lambda: valkey):
            # Un correo distinto en cada intento, para que solo cuente el límite por IP. Cada intento trae otra IP
            # inventada: ninguna cuenta.
            for n in range(sessions.MAX_FAILS_IP):
                ip = ip_vista(DESPLIEGUE, PORTAL, '6.6.6.%d, 198.51.100.7' % n)
                sessions.register_fail('nadie%d@ejemplo.test' % n, ip)
            self.assertTrue(sessions.is_locked('otro@ejemplo.test', ip_vista(DESPLIEGUE, PORTAL, '198.51.100.7')))
            self.assertFalse(sessions.is_locked('otro@ejemplo.test',
                                                ip_vista(DESPLIEGUE, PORTAL, '6.6.6.6, 198.51.100.8')))


class UvicornFueraDeDocker(unittest.TestCase):
    def test_5_por_omision_uvicorn_le_cree_a_127_0_0_1(self):
        # Por qué README.md pide --forwarded-allow-ips="": sin la opción ni la variable, uvicorn confía en el portal
        # de `npm run dev` (127.0.0.1) y la IP la elige quien llama.
        with mock.patch.dict(os.environ, clear=True):
            confianza = Config('cirdan.api.main:app').forwarded_allow_ips
        self.assertEqual(ip_vista(confianza, '127.0.0.1', '6.6.6.6'), '6.6.6.6')

    def test_6_con_la_opcion_del_readme_no_le_cree_a_nadie(self):
        with mock.patch.dict(os.environ, {'FORWARDED_ALLOW_IPS': '*'}):
            confianza = Config('cirdan.api.main:app', forwarded_allow_ips='').forwarded_allow_ips
        self.assertEqual(ip_vista(confianza, '127.0.0.1', '6.6.6.6'), '127.0.0.1')
        self.assertEqual(ip_vista(confianza, '::1', '6.6.6.6'), '::1')


class Origenes(unittest.TestCase):
    def origenes(self, valor):
        entorno = {} if valor is None else {'ALLOWED_ORIGINS': valor}
        with mock.patch.dict(os.environ, entorno, clear=True), mock.patch.object(cfg, '_env_file', lambda: {}):
            return cfg.origenes_permitidos()

    def test_7_vacia_o_sin_poner_es_la_lista_local(self):
        # docker-compose.yml la pasa con ${ALLOWED_ORIGINS:-}: vacía no puede rechazar toda escritura (10401).
        for valor in (None, '', ' ', ' , '):
            with self.subTest(valor=valor):
                self.assertEqual(self.origenes(valor), cfg.ORIGENES_LOCALES.split(','))

    def test_8_la_declarada_sin_espacios_ni_vacios(self):
        self.assertEqual(self.origenes(' https://pruebas.lowtidesec.com , ,https://lowtidesec.com,'),
                         ['https://pruebas.lowtidesec.com', 'https://lowtidesec.com'])


if __name__ == '__main__':
    unittest.main()

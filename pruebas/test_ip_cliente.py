"""Pruebas de la IP del cliente del login y de los orígenes permitidos (RC-277), sin red ni Valkey.

La IP con que el login cuenta sus 20 fallos la da uvicorn con --proxy-headers (Dockerfile): de derecha a izquierda,
la primera de X-Forwarded-For que no está en FORWARDED_ALLOW_IPS. Estas pruebas usan el ProxyHeadersMiddleware real de
uvicorn con la lista del despliegue (docker-compose.despliegue.yml, la revisa test_despliegue.py test_7) y con la del
README fuera de Docker (--forwarded-allow-ips=""), y el contador por IP de sessions (register_fail e is_locked) con un
Valkey falso. El camino del login con take_login_attempt lo prueban test_login_sin_red.py y test_auth.py. Corren dentro
del contenedor, porque piden uvicorn y redis:

    docker compose run --rm -v "$PWD/pruebas:/app/pruebas:ro" api python -m unittest -v pruebas/test_ip_cliente.py
"""
import asyncio
import json
import os
import subprocess
import sys
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

    def test_9_escrita_como_el_origin_del_navegador(self):
        # El navegador manda esquema y host en minúsculas, sin barra ni puerto por omisión. Escrita de otra forma, la
        # regla de RC-286 la veía https y el filtro de Origin rechazaba todo POST.
        valor = ' HTTPS://Pruebas.LowTideSec.com:443/ ,http://LOCALHOST:80,http://localhost:3000/'
        self.assertEqual(self.origenes(valor),
                         ['https://pruebas.lowtidesec.com', 'http://localhost', 'http://localhost:3000'])
        # Con ruta o sin host no es un origen: se queda tal cual y no coincide con ningún Origin.
        self.assertEqual(self.origenes('https://lowtidesec.com/app,lowtidesec.com'),
                         ['https://lowtidesec.com/app', 'lowtidesec.com'])

    def test_10_el_filtro_de_la_api_usa_la_misma_lista(self):
        # La API arma su lista al importar cirdan.api.main: se importa en otro proceso con cada valor y se manda un
        # POST por ASGI, sin lifespan, base ni red. 404 es que el filtro lo dejó pasar.
        for valor, pasa, no_pasa in (('', 'http://localhost:3000', 'https://otro.example'),
                                     (' HTTPS://Pruebas.lowtidesec.com:443/ ', 'https://pruebas.lowtidesec.com',
                                      'http://localhost:3000')):
            with self.subTest(valor=valor):
                r = subprocess.run([sys.executable, '-c', POST_POR_ASGI, pasa, no_pasa],
                                   env=dict(os.environ, ALLOWED_ORIGINS=valor), capture_output=True, text=True,
                                   timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr[-2000:])
                self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1]), [404, 403])


POST_POR_ASGI = '''
import asyncio, json, sys
from cirdan.api import main

async def post(origen):
    estado = {}
    async def recibir():
        return {'type': 'http.request', 'body': b'', 'more_body': False}
    async def enviar(mensaje):
        if mensaje['type'] == 'http.response.start':
            estado['codigo'] = mensaje['status']
    await main.app({'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': 'POST',
                    'scheme': 'http', 'path': '/no-existe-rc277', 'raw_path': b'/no-existe-rc277', 'query_string': b'',
                    'root_path': '', 'headers': [(b'host', b'api'), (b'origin', origen.encode())],
                    'client': ('127.0.0.1', 1), 'server': ('api', 8000)}, recibir, enviar)
    return estado['codigo']

print(json.dumps([asyncio.run(post(sys.argv[1])), asyncio.run(post(sys.argv[2]))]))
'''


if __name__ == '__main__':
    unittest.main()

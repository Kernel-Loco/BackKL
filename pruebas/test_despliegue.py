"""Pruebas del compose del despliegue (#49, RC-91), sin base ni red.

Arman la config de docker-compose.yml con docker-compose.despliegue.yml (`docker compose config`, que no crea nada
ni baja imágenes) con un .env de valores falsos y revisan lo que pide el Hecho cuando y sus comentarios: las cuentas
de demo apagadas aunque el .env diga true (comentario 10420), ALLOWED_ORIGINS en la API (10312), rotación del registro
(10266), ningún puerto abierto a la red, el túnel sin acceso a la API y FORWARDED_ALLOW_IPS con las IP fijas del portal
y de cloudflared. Sin docker en el PATH se saltan.

    python -m unittest -v pruebas/test_despliegue.py
"""
import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
ARCHIVOS = ['docker-compose.yml', 'docker-compose.despliegue.yml']
ORIGEN = 'https://lowtidesec.com'

ENV_FALSO = {
    'POSTGRES_PASSWORD': 'CIRDAN_FAKE_pg',
    'CIRDAN_APP_PASSWORD': 'CIRDAN_FAKE_app',
    'VALKEY_PASSWORD': 'CIRDAN_FAKE_valkey',
    'TOTP_ENCRYPTION_KEY': 'CIRDAN_FAKE_totp',
    'ALLOWED_ORIGINS': ORIGEN,
    'TUNNEL_TOKEN': 'CIRDAN_FAKE_tunel',
    # Lo que un .env copiado de una PC de desarrollo traería: el despliegue tiene que ganarle.
    'DEMO_ACCOUNTS': 'true',
    'DEMO_EXPLORER': 'true',
    'COOKIE_SECURE': 'false',
    'FORWARDED_ALLOW_IPS': '*',
}


def _config(env):
    """Corre `docker compose config` con solo las variables de env. Devuelve (código de salida, salida)."""
    with tempfile.TemporaryDirectory() as tmp:
        archivo = Path(tmp) / 'despliegue.env'
        archivo.write_text(''.join('%s=%s\n' % kv for kv in env.items()), encoding='utf-8')
        # Sin las variables del compose que traiga la terminal: le ganarían al archivo de valores falsos.
        base = {k: v for k, v in os.environ.items()
                if k.upper() not in ENV_FALSO and not k.upper().startswith(('COMPOSE_', 'PG', 'POSTGRES_', 'VALKEY_',
                                                                          'PORTAL_', 'DOMINIOS_', 'ORGS_'))}
        cmd = ['docker', 'compose', '--project-directory', str(RAIZ), '-p', 'prueba-despliegue',
               '--env-file', str(archivo)]
        for a in ARCHIVOS:
            cmd += ['-f', str(RAIZ / a)]
        r = subprocess.run(cmd + ['config', '--format', 'json'], capture_output=True, text=True, env=base,
                           timeout=60, encoding='utf-8')
        return r.returncode, r.stdout if r.returncode == 0 else r.stderr


@unittest.skipUnless(shutil.which('docker'), 'sin docker en el PATH')
class Despliegue(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rc, salida = _config(ENV_FALSO)
        if rc != 0:
            raise AssertionError('docker compose config falló: ' + salida[-500:])
        cls.cfg = json.loads(salida)
        cls.svc = cls.cfg['services']

    def test_1_servicios_del_despliegue(self):
        self.assertEqual(set(self.svc), {'db', 'valkey', 'api', 'demo-accounts', 'portal', 'cloudflared'})

    def test_2_cuentas_de_demo_y_explorador_apagados(self):
        self.assertEqual(self.svc['demo-accounts']['environment']['DEMO_ACCOUNTS'], 'false')
        self.assertEqual(self.svc['api']['environment']['DEMO_EXPLORER'], 'false')

    def test_3_origen_y_cookie_segura(self):
        self.assertEqual(self.svc['api']['environment']['ALLOWED_ORIGINS'], ORIGEN)
        self.assertEqual(self.svc['demo-accounts']['environment']['ALLOWED_ORIGINS'], ORIGEN)
        self.assertEqual(self.svc['api']['environment']['COOKIE_SECURE'], 'true')

    def test_4_variables_obligatorias(self):
        for falta in ('ALLOWED_ORIGINS', 'TUNNEL_TOKEN'):
            env = {k: v for k, v in ENV_FALSO.items() if k != falta}
            rc, salida = _config(env)
            self.assertNotEqual(rc, 0, falta)
            self.assertIn('Falta ' + falta, salida)

    def test_5_ningun_puerto_abierto_a_la_red(self):
        for nombre, s in self.svc.items():
            for p in s.get('ports', []):
                self.assertEqual(p.get('host_ip'), '127.0.0.1', '%s publica %s' % (nombre, p))
        self.assertNotIn('ports', self.svc['portal'])
        self.assertNotIn('ports', self.svc['cloudflared'])

    def test_6_tunel_sin_acceso_a_la_api(self):
        redes = {n: set(s.get('networks', {})) for n, s in self.svc.items()}
        self.assertEqual(redes['cloudflared'], {'borde'})
        self.assertFalse(redes['cloudflared'] & (redes['api'] | redes['db'] | redes['valkey']))
        # La única red que comparten el portal y la API es la interna, que no sale a internet.
        self.assertEqual(redes['portal'] & redes['api'], {'interna'})
        self.assertTrue(self.cfg['networks']['interna'].get('internal'))
        self.assertNotIn('interna', redes['db'] | redes['valkey'])

    def test_7_ip_del_cliente_solo_del_portal_y_del_tunel(self):
        permitidas = set(self.svc['api']['environment']['FORWARDED_ALLOW_IPS'].split(','))
        portal = self.svc['portal']['networks']['interna']['ipv4_address']
        tunel = self.svc['cloudflared']['networks']['borde']['ipv4_address']
        self.assertEqual(permitidas, {portal, tunel})
        # Cada IP fija cae en la subred de su red.
        for ip, red in ((portal, 'interna'), (tunel, 'borde')):
            subred = self.cfg['networks'][red]['ipam']['config'][0]['subnet']
            self.assertIn(ipaddress.ip_address(ip), ipaddress.ip_network(subred))

    def test_8_rotacion_del_registro(self):
        for nombre, s in self.svc.items():
            log = s.get('logging', {})
            self.assertEqual(log.get('driver'), 'json-file', nombre)
            self.assertEqual(log.get('options'), {'max-size': '10m', 'max-file': '3'}, nombre)

    def test_9_imagen_del_tunel_fija_y_portal_hacia_la_api(self):
        imagen = self.svc['cloudflared']['image']
        self.assertRegex(imagen, r'^cloudflare/cloudflared:\d{4}\.\d+\.\d+$')
        self.assertEqual(self.svc['portal']['environment']['API_INTERNAL_URL'], 'http://api:8000')
        self.assertEqual(self.svc['portal']['build']['args']['API_INTERNAL_URL'], 'http://api:8000')
        self.assertEqual(self.svc['cloudflared']['environment']['TUNNEL_TOKEN'], 'CIRDAN_FAKE_tunel')


if __name__ == '__main__':
    unittest.main()

"""Pruebas del compose del despliegue (#49, RC-91), sin base ni red.

Arman la config de docker-compose.yml con docker-compose.despliegue.yml (`docker compose config`, que no crea nada
ni baja imágenes) con un .env de valores falsos y revisan lo que pide el Hecho cuando y sus comentarios: las cuentas
de demo apagadas aunque el .env diga true (comentario 10420), ALLOWED_ORIGINS en la API (10312), rotación del registro
(10266), ningún puerto publicado en el host, el túnel sin acceso a la API, el portal fuera del alcance del host,
FORWARDED_ALLOW_IPS con las IP fijas del portal y de cloudflared, y lo que arregló la revisión de riesgo de RC-91
(keep-alive de uvicorn, subredes y nombres de contenedor). Sin docker en el PATH se saltan.

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


def _config(env, proyecto='prueba-despliegue'):
    """Corre `docker compose config` con solo las variables de env. Devuelve (código de salida, salida). Con
    `proyecto=None` no pasa `-p` y el nombre del proyecto sale de env (COMPOSE_PROJECT_NAME) o de la carpeta."""
    with tempfile.TemporaryDirectory() as tmp:
        archivo = Path(tmp) / 'despliegue.env'
        archivo.write_text(''.join('%s=%s\n' % kv for kv in env.items()), encoding='utf-8')
        # Sin las variables del compose que traiga la terminal: le ganarían al archivo de valores falsos.
        base = {k: v for k, v in os.environ.items()
                if k.upper() not in ENV_FALSO and not k.upper().startswith(('COMPOSE_', 'PG', 'POSTGRES_', 'VALKEY_',
                                                                          'PORTAL_', 'DOMINIOS_', 'ORGS_'))}
        cmd = ['docker', 'compose', '--project-directory', str(RAIZ)] + (['-p', proyecto] if proyecto else []) + [
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

    def test_5_ningun_puerto_publicado_en_el_host(self):
        # Ni en 127.0.0.1: docker-compose.yml publica db, valkey y api en loopback y el despliegue los quita.
        for nombre, s in self.svc.items():
            self.assertFalse(s.get('ports'), '%s publica %s' % (nombre, s.get('ports')))

    def test_6_tunel_sin_acceso_a_la_api(self):
        redes = {n: set(s.get('networks', {})) for n, s in self.svc.items()}
        self.assertEqual(redes['cloudflared'], {'borde', 'salida'})
        self.assertFalse(redes['cloudflared'] & (redes['api'] | redes['db'] | redes['valkey']))
        # salida es solo de cloudflared: por ella llega a Cloudflare y nadie más la comparte.
        self.assertEqual([n for n, r in redes.items() if 'salida' in r], ['cloudflared'])
        # La única red que comparten el portal y la API es la interna.
        self.assertEqual(redes['portal'] & redes['api'], {'interna'})
        self.assertEqual(redes['portal'], {'interna', 'borde'})
        self.assertNotIn('interna', redes['db'] | redes['valkey'])

    def test_6b_el_host_no_llega_al_portal(self):
        # Sin salida a internet y sin IP del host en la red: un proceso de la máquina no llega al portal por la IP
        # de su red ni elige su IP con X-Forwarded-For (hallazgo 8). Se probó en una pila aislada.
        for red in ('interna', 'borde'):
            cfg = self.cfg['networks'][red]
            self.assertTrue(cfg.get('internal'), red)
            self.assertEqual(cfg.get('driver_opts', {}).get('com.docker.network.bridge.gateway_mode_ipv4'),
                             'isolated', red)

    def test_7_ip_del_cliente_solo_del_portal_y_del_tunel(self):
        permitidas = set(self.svc['api']['environment']['FORWARDED_ALLOW_IPS'].split(','))
        portal = self.svc['portal']['networks']['interna']['ipv4_address']
        tunel = self.svc['cloudflared']['networks']['borde']['ipv4_address']
        self.assertEqual(permitidas, {portal, tunel})
        # Cada IP fija cae en la subred de su red.
        for ip, red in ((portal, 'interna'), (tunel, 'borde')):
            subred = self.cfg['networks'][red]['ipam']['config'][0]['subnet']
            self.assertIn(ipaddress.ip_address(ip), ipaddress.ip_network(subred))

    def test_7b_subredes_fuera_de_los_rangos_comunes(self):
        # Los que Docker reparte solo (172.16.0.0/12 y 192.168.0.0/16), que incluyen la VPC por omisión de AWS
        # (172.31.0.0/16) (hallazgo 14).
        comunes = [ipaddress.ip_network(r) for r in ('172.16.0.0/12', '192.168.0.0/16')]
        for red in ('interna', 'borde'):
            subred = ipaddress.ip_network(self.cfg['networks'][red]['ipam']['config'][0]['subnet'])
            for comun in comunes:
                self.assertFalse(subred.overlaps(comun), '%s %s choca con %s' % (red, subred, comun))

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

    def test_10_keep_alive_de_uvicorn_mayor_que_el_de_node(self):
        # El agente de Node suelta una conexión ociosa a los 5 s. uvicorn tiene que tardar más (hallazgo 13).
        self.assertGreater(int(self.svc['api']['environment']['UVICORN_TIMEOUT_KEEP_ALIVE']), 5)

    def test_11_portal_y_tunel_sin_nombre_de_contenedor_fijo(self):
        # Un plan B desde otra carpeta no choca con estos nombres (hallazgo 16). Los de db, valkey y api vienen de
        # docker-compose.yml y no se cambian.
        for nombre in ('portal', 'cloudflared'):
            self.assertNotIn('container_name', self.svc[nombre], nombre)

    def test_12_el_plan_b_tiene_su_propio_proyecto_y_volumen(self):
        # R1 de la revisión de RC-91: C:\lowtide-planb\BackKL daría el proyecto 'backkl', el mismo que la carpeta de
        # desarrollo, y los dos usarían el mismo volumen de la base. COMPOSE_PROJECT_NAME en el .env del plan B lo
        # evita.
        rc, salida = _config(dict(ENV_FALSO, COMPOSE_PROJECT_NAME='lowtide-planb'), proyecto=None)
        self.assertEqual(rc, 0, salida[-500:])
        cfg = json.loads(salida)
        self.assertEqual(cfg['name'], 'lowtide-planb')
        self.assertEqual(cfg['volumes']['cirdan-pg16-data']['name'], 'lowtide-planb_cirdan-pg16-data')
        ejemplo = (RAIZ / '.env.example').read_text(encoding='utf-8')
        self.assertIn('# COMPOSE_PROJECT_NAME=lowtide-planb\n', ejemplo)


if __name__ == '__main__':
    unittest.main()

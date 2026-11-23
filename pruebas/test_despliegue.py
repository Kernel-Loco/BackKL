"""Pruebas del compose del despliegue (#49, RC-91), sin base ni red.

Arman la config de docker-compose.yml con docker-compose.despliegue.yml (`docker compose config`, que no crea nada
ni baja imágenes) con un .env de valores falsos y revisan lo que pide el Hecho cuando y sus comentarios: las cuentas
de demo apagadas aunque el .env diga true (comentario 10420), ALLOWED_ORIGINS en la API (10312), rotación del registro
(10266), ningún puerto publicado en el host, el túnel sin acceso a la API, el portal fuera del alcance del host,
FORWARDED_ALLOW_IPS con las IP fijas del portal y de cloudflared, y lo que arregló la revisión de riesgo de RC-91
(keep-alive de uvicorn, subredes y nombres de contenedor). Sin docker en el PATH se saltan.

    python -m unittest -v pruebas/test_despliegue.py
"""
import ast
import ipaddress
import json
import os
import re
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
    'CARTA_KEY_VAULT_SECRET_URL': 'https://fake-vault.vault.azure.net/secrets/carta-key/0123456789abcdef0123456789abcdef',
    # Lo que un .env copiado de una PC de desarrollo traería: el despliegue tiene que ganarle.
    'DEMO_ACCOUNTS': 'true',
    'DEMO_EXPLORER': 'true',
    'API_DOCS': 'true',
    'COOKIE_SECURE': 'false',
    'FORWARDED_ALLOW_IPS': '*',
}


def _config(env, proyecto='prueba-despliegue', archivos=ARCHIVOS, perfiles=()):
    """Corre `docker compose config` con solo las variables de env. Devuelve (código de salida, salida). Con
    `proyecto=None` no pasa `-p` y el nombre del proyecto sale de env (COMPOSE_PROJECT_NAME) o de la carpeta."""
    with tempfile.TemporaryDirectory() as tmp:
        archivo = Path(tmp) / 'despliegue.env'
        archivo.write_text(''.join('%s=%s\n' % kv for kv in env.items()), encoding='utf-8')
        # Sin las variables del compose que traiga la terminal: le ganarían al archivo de valores falsos.
        base = {k: v for k, v in os.environ.items()
                if k.upper() not in ENV_FALSO and not k.upper().startswith(('COMPOSE_', 'PG', 'POSTGRES_', 'VALKEY_',
                                                                          'PORTAL_', 'DOMINIOS_', 'ORGS_', 'TOTP_'))}
        cmd = ['docker', 'compose', '--project-directory', str(RAIZ)] + (['-p', proyecto] if proyecto else []) + [
            '--env-file', str(archivo)]
        for a in archivos:
            cmd += ['-f', str(RAIZ / a)]
        for perfil in perfiles:
            cmd += ['--profile', perfil]
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
        # Sin /openapi.json, /docs ni /redoc aunque el .env diga true (comentario 10063). Qué hace la API con false lo
        # prueba pruebas/test_documentacion_api.py.
        self.assertEqual(self.svc['api']['environment']['API_DOCS'], 'false')

    def test_3b_el_enlace_al_correo_sale_del_origen_publicado(self):
        # M4 de RC-63: PORTAL_URL vacía, aunque el .env traiga la de la PC, para que la API use el primer origen de
        # ALLOWED_ORIGINS (pruebas/test_enlace_sin_red.py, test_12b) también en el plan B de pruebas.
        rc, salida = _config(dict(ENV_FALSO, PORTAL_URL='http://localhost:3000',
                                  ALLOWED_ORIGINS='https://pruebas.lowtidesec.com'))
        self.assertEqual(rc, 0, salida[-500:])
        api = json.loads(salida)['services']['api']['environment']
        self.assertEqual((api['PORTAL_URL'], api['ALLOWED_ORIGINS']), ('', 'https://pruebas.lowtidesec.com'))
        self.assertEqual(api['CORREO_API_URL'], 'https://api.resend.com/emails')

    def test_3_origen_y_cookie_segura(self):
        self.assertEqual(self.svc['api']['environment']['ALLOWED_ORIGINS'], ORIGEN)
        self.assertEqual(self.svc['demo-accounts']['environment']['ALLOWED_ORIGINS'], ORIGEN)
        self.assertEqual(self.svc['api']['environment']['COOKIE_SECURE'], 'true')
        self.assertEqual(self.svc['api']['environment']['CARTA_ALTA_ENABLED'], 'true')
        self.assertEqual(self.svc['api']['environment']['CARTA_KEY_VAULT_SECRET_URL'],
                         ENV_FALSO['CARTA_KEY_VAULT_SECRET_URL'])

    def test_4_variables_obligatorias(self):
        for falta in ('ALLOWED_ORIGINS', 'TUNNEL_TOKEN', 'CARTA_KEY_VAULT_SECRET_URL'):
            env = {k: v for k, v in ENV_FALSO.items() if k != falta}
            rc, salida = _config(env)
            self.assertNotEqual(rc, 0, falta)
            self.assertIn('Falta ' + falta, salida)

    def test_4b_el_volumen_de_cartas_se_puede_cambiar_al_restaurar(self):
        carta = self.svc['api']['volumes'][0]
        self.assertEqual(carta['type'], 'volume')
        self.assertEqual(carta['source'], 'prueba-despliegue_cirdan-cartas')
        rc, salida = _config(dict(ENV_FALSO, CARTA_VOLUME_NAME='cartas-restauradas'))
        self.assertEqual(rc, 0, salida[-500:])
        cfg = json.loads(salida)
        self.assertEqual(cfg['services']['api']['volumes'][0]['source'], 'cartas-restauradas')
        self.assertEqual(cfg['volumes']['cirdan-cartas']['name'], 'cartas-restauradas')

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
        for red in ('interna', 'borde', 'default'):
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

    def test_13_llave_del_mfa_desde_key_vault(self):
        # En la VM la llave del MFA no va en el .env: solo la URL de su secreto en Key Vault (opción 4 de RC-91). La
        # pila tiene que armarse sin TOTP_ENCRYPTION_KEY y la API y el script de demo reciben la URL. Que no vengan
        # las dos lo revisa la API al arrancar (pruebas/test_llave_totp.py).
        url = 'https://kv-lowtide.vault.azure.net/secrets/totp-encryption-key/0123456789abcdef0123456789abcdef'
        env = {k: v for k, v in ENV_FALSO.items() if k != 'TOTP_ENCRYPTION_KEY'}
        rc, salida = _config(dict(env, TOTP_KEY_VAULT_SECRET_URL=url))
        self.assertEqual(rc, 0, salida[-500:])
        svc = json.loads(salida)['services']
        for nombre in ('api', 'demo-accounts'):
            self.assertEqual(svc[nombre]['environment']['TOTP_KEY_VAULT_SECRET_URL'], url, nombre)
            self.assertEqual(svc[nombre]['environment']['TOTP_ENCRYPTION_KEY'], '', nombre)
        # Con la llave en el .env (desarrollo, CI y plan B) la URL llega vacía.
        self.assertEqual(self.svc['api']['environment']['TOTP_KEY_VAULT_SECRET_URL'], '')
        self.assertEqual(self.svc['api']['environment']['TOTP_ENCRYPTION_KEY'], 'CIRDAN_FAKE_totp')

    def test_13b_llave_de_las_huellas_desde_key_vault(self):
        # RC-330: la llave de las huellas de contraseña sigue la misma regla que la del MFA. La API y el script de demo
        # reciben las dos variables; con la llave en el .env la URL llega vacía.
        url = 'https://kv-lowtide.vault.azure.net/secrets/password-hash-key/0123456789abcdef0123456789abcdef'
        rc, salida = _config(dict(ENV_FALSO, PASSWORD_HASH_KEY_VAULT_SECRET_URL=url))
        self.assertEqual(rc, 0, salida[-500:])
        svc = json.loads(salida)['services']
        for nombre in ('api', 'demo-accounts'):
            self.assertEqual(svc[nombre]['environment']['PASSWORD_HASH_KEY_VAULT_SECRET_URL'], url, nombre)
            self.assertEqual(svc[nombre]['environment']['PASSWORD_HASH_ENCRYPTION_KEY'], '', nombre)
        rc, salida = _config(dict(ENV_FALSO, PASSWORD_HASH_ENCRYPTION_KEY='CIRDAN_FAKE_huellas'))
        self.assertEqual(rc, 0, salida[-500:])
        svc = json.loads(salida)['services']
        for nombre in ('api', 'demo-accounts'):
            self.assertEqual(svc[nombre]['environment']['PASSWORD_HASH_ENCRYPTION_KEY'], 'CIRDAN_FAKE_huellas', nombre)
            self.assertEqual(svc[nombre]['environment']['PASSWORD_HASH_KEY_VAULT_SECRET_URL'], '', nombre)

    def test_14_solo_la_api_llega_a_imds(self):
        # Hallazgo 0 de la revisión de la opción 4 de RC-91: la regla de DOCKER-USER de docs/despliegue.md deja pasar
        # a 169.254.169.254 solo la IP fija de la API. Esa IP cae en la subred de default, fuera del rango que Docker
        # reparte solo, y ningún otro servicio la tiene. La regla misma se prueba en vivo en la VM.
        api = ipaddress.ip_address(self.svc['api']['networks']['default']['ipv4_address'])
        ipam = self.cfg['networks']['default']['ipam']['config'][0]
        subred, rango = ipaddress.ip_network(ipam['subnet']), ipaddress.ip_network(ipam['ip_range'])
        self.assertIn(api, subred)
        self.assertTrue(rango.subnet_of(subred))
        self.assertNotIn(api, rango)
        en_default = [n for n, s in self.svc.items() if 'default' in (s.get('networks') or {'default': None})]
        self.assertEqual(set(en_default), {'api', 'db', 'valkey', 'demo-accounts'})
        for nombre in en_default:
            if nombre != 'api':
                s = self.svc[nombre]
                self.assertNotIn('ipv4_address', (s.get('networks') or {}).get('default') or {}, nombre)
                # R4 de la ronda 2: sin sockets crudos no envenenan el ARP para quedarse con la IP de la API.
                self.assertIn('NET_RAW', s.get('cap_drop') or [], nombre)
        doc = (RAIZ / 'docs' / 'despliegue.md').read_text(encoding='utf-8')
        # R3 de la ronda 2: sin la regla Docker no arranca, y se vuelve a poner al reiniciar Docker.
        unidad = doc[doc.index('[Unit]'):doc.index('EOF', doc.index('[Unit]'))]
        for linea in ('Before=docker.service', 'PartOf=docker.service', 'RequiredBy=docker.service'):
            self.assertIn('\n' + linea + '\n', unidad)
        regla = '-d 169.254.169.254/32 ! -s %s/32 -j DROP' % api
        self.assertEqual(doc.count('iptables -C DOCKER-USER ' + regla), 1)
        self.assertEqual(doc.count('iptables -I DOCKER-USER ' + regla), 1)
        self.assertEqual(set(re.findall(r'! -s ([0-9.]+)/32', doc)), {str(api)})

    def test_16_programador_solo_con_su_profile_y_sin_imds(self):
        # RC-52: el programador no se enciende con `up -d` (test_1). Con su profile sale por default, sin puertos, sin
        # la IP fija de la API ni NET_RAW, con el registro rotado y sin las llaves de Key Vault.
        rc, salida = _config(ENV_FALSO, perfiles=('programador',))
        self.assertEqual(rc, 0, salida[-500:])
        cfg = json.loads(salida)
        s = cfg['services']['programador']
        self.assertEqual(s['command'], ['python', '-m', 'cirdan.programador'])
        self.assertEqual(s['profiles'], ['programador'])
        self.assertFalse(s.get('ports'))
        self.assertEqual(set(s.get('networks') or {'default': None}), {'default'})
        self.assertNotIn('ipv4_address', (s.get('networks') or {}).get('default') or {})
        self.assertIn('NET_RAW', s.get('cap_drop') or [])
        self.assertEqual(s['logging'], cfg['services']['db']['logging'])
        self.assertTrue(s['init'])
        self.assertEqual(s['stop_grace_period'], '1m0s')  # tiempos-3: detener() alcanza a cerrar los escaneos
        for llave in ('TOTP', 'PASSWORD_HASH', 'CARTA', 'IA_', 'CORREO'):
            self.assertEqual([k for k in s['environment'] if k.startswith(llave)], [], llave)
        # El HEALTHCHECK de la imagen es el de la API (/health en el 8000) y el programador no abre puertos: sin
        # quitarlo queda 'unhealthy' aunque funcione. Tampoco lo vuelve a poner el compose de las imágenes firmadas.
        self.assertEqual(s.get('healthcheck'), {'disable': True})
        con_imagenes = dict(ENV_FALSO, LOWTIDE_API_IMAGEN='ghcr.io/ejemplo/api@sha256:' + '0' * 64,
                            LOWTIDE_PORTAL_IMAGEN='ghcr.io/ejemplo/portal@sha256:' + '0' * 64)
        rc, salida = _config(con_imagenes, archivos=ARCHIVOS + ['docker-compose.imagenes.yml'],
                             perfiles=('programador',))
        self.assertEqual(rc, 0, salida[-500:])
        self.assertEqual(json.loads(salida)['services']['programador'].get('healthcheck'), {'disable': True})
        # En la VM va COMPOSE_PROFILES=programador en el .env (docs/despliegue.md, 'Escaneos programados'): así cada
        # `up -d --build` también lo recrea con el código nuevo.
        rc, salida = _config(dict(ENV_FALSO, COMPOSE_PROFILES='programador'))
        self.assertEqual(rc, 0, salida[-500:])
        self.assertIn('programador', json.loads(salida)['services'])

    def test_15_el_healthcheck_espera_a_la_llave_de_key_vault(self):
        # Hallazgos 8, 11 y 12: la API puede tardar hasta keyvault.PLAZO en leer cada llave antes de rendirse, y desde
        # RC-330 lee dos (la del MFA y la de las huellas). El periodo de arranque del HEALTHCHECK tiene que ser mayor
        # que las dos juntas, para que no la marque unhealthy antes.
        fuente = (RAIZ / 'cirdan' / 'auth' / 'keyvault.py').read_text(encoding='utf-8')
        plazo = next(ast.literal_eval(n.value) for n in ast.parse(fuente).body
                     if isinstance(n, ast.Assign) and [getattr(x, 'id', None) for x in n.targets] == ['PLAZO'])
        dockerfile = (RAIZ / 'Dockerfile').read_text(encoding='utf-8')
        inicio = int(re.search(r'HEALTHCHECK .*--start-period=(\d+)s', dockerfile).group(1))
        main = (RAIZ / 'cirdan' / 'api' / 'main.py').read_text(encoding='utf-8')
        lecturas = len(re.findall(r'\b(?:totp|passwords)\.comprobar_llave\(', main))
        self.assertEqual(lecturas, 2)
        self.assertGreater(inicio, lecturas * plazo + 10)


class ImagenDeLaApi(unittest.TestCase):
    def test_1_uvicorn_sin_encabezado_server(self):
        # Comentario 10063: el CMD del Dockerfile manda --no-server-header. pruebas/test_documentacion_api.py arranca la
        # API con este mismo CMD y revisa que no salga el encabezado. No necesita docker.
        texto = re.sub(r'\\\n\s*', '', (RAIZ / 'Dockerfile').read_text(encoding='utf-8'))
        cmds = [l[len('CMD'):].strip() for l in texto.splitlines() if l.startswith('CMD ')]
        self.assertEqual(json.loads(cmds[-1]), ['python', '-m', 'uvicorn', 'cirdan.api.main:app', '--host', '0.0.0.0',
                                                '--port', '8000', '--proxy-headers', '--no-server-header'])

    def test_2_documentacion_apagada_por_omision_en_desarrollo(self):
        # RC-303: sin API_DOCS en el .env la API de la PC tampoco publica /openapi.json, /docs ni /redoc. Que la API
        # use false cuando no le llega la variable lo prueba pruebas/test_documentacion_api.py. No necesita docker.
        compose = (RAIZ / 'docker-compose.yml').read_text(encoding='utf-8')
        self.assertEqual(re.findall(r'^\s*API_DOCS:\s*(.+?)\s*$', compose, re.M), ['${API_DOCS:-false}'])
        ejemplo = (RAIZ / '.env.example').read_text(encoding='utf-8')
        self.assertEqual(re.findall(r'^API_DOCS=(.*)$', ejemplo, re.M), ['false'])


@unittest.skipUnless(shutil.which('docker'), 'sin docker en el PATH')
class ComposeDeDesarrollo(unittest.TestCase):
    def test_1_la_api_recibe_allowed_origins(self):
        # RC-277: con solo docker-compose.yml (el plan B sin el archivo del despliegue, o la PC de desarrollo) la API
        # recibe ALLOWED_ORIGINS del .env. Sin poner llega vacía, y la API usa la lista local (test_ip_cliente.py).
        env = {k: v for k, v in ENV_FALSO.items() if k != 'ALLOWED_ORIGINS'}
        for extra, esperado in (({}, ''), ({'ALLOWED_ORIGINS': ORIGEN}, ORIGEN)):
            with self.subTest(esperado=esperado):
                rc, salida = _config({**env, **extra}, archivos=['docker-compose.yml'])
                self.assertEqual(rc, 0, salida[-500:])
                api = json.loads(salida)['services']['api']['environment']
                self.assertEqual(api['ALLOWED_ORIGINS'], esperado)


if __name__ == '__main__':
    unittest.main()

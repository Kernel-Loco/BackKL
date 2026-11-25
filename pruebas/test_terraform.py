"""Pruebas de la infraestructura como código (#81, RC-132), sin nube, sin base y sin red.

Leen infra/terraform y revisan lo que pide el Hecho cuando: el grupo de seguridad solo abre 22 y 443 a las IPs del
equipo, el estado y las variables no van a git, Terraform no lee secretos (así no quedan en su estado) y cloud-init
pone la misma regla de IMDS que docs/despliegue.md con la IP fija de la API del compose. También corren el script
que arma el .env de la VM sobre el .env.example de verdad. `terraform validate` y Trivy corren en el job terraform
del CI (.github/workflows/pruebas.yml).

    python -m unittest -v pruebas/test_terraform.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
TF = RAIZ / 'infra' / 'terraform'
CLOUD_INIT = TF / 'cloud-init.yaml.tftpl'


def leer(ruta):
    return Path(ruta).read_text(encoding='utf-8')


def todo_el_terraform():
    return '\n'.join(leer(p) for p in sorted(TF.glob('*.tf')))


def archivo_de_cloud_init(ruta):
    """Contenido de un write_files de cloud-init, sin la sangría de YAML."""
    texto = leer(CLOUD_INIT)
    inicio = texto.index('  - path: ' + ruta + '\n')
    inicio = texto.index('    content: |\n', inicio) + len('    content: |\n')
    fin = re.compile(r'^(  - path: |runcmd:)', re.M).search(texto, inicio).start()
    return textwrap.dedent(texto[inicio:fin]).strip('\n') + '\n'


def con_variables(texto, **valores):
    """Lo que hace templatefile con las variables de main.tf."""
    for nombre, valor in valores.items():
        texto = texto.replace('${' + nombre + '}', valor)
    restos = re.findall(r'\$\{[^}]*\}', texto)
    if restos:
        raise AssertionError('variables sin valor en la plantilla: ' + ', '.join(restos))
    return texto


class GrupoDeSeguridad(unittest.TestCase):
    def setUp(self):
        self.reglas = re.findall(r'security_rule \{(.*?)\n  \}', leer(TF / 'main.tf'), re.S)

    def test_1_solo_22_y_443_y_solo_desde_las_ips_del_equipo(self):
        self.assertEqual(len(self.reglas), 2)
        puertos = set()
        for regla in self.reglas:
            self.assertIn('direction                  = "Inbound"', regla)
            self.assertIn('access                     = "Allow"', regla)
            self.assertIn('source_address_prefixes    = var.ips_equipo', regla)
            self.assertNotRegex(regla, r'source_address_prefix\s*=')
            puertos.add(re.search(r'destination_port_range\s*=\s*"(\d+)"', regla).group(1))
        self.assertEqual(puertos, {'22', '443'})

    def test_2_las_variables_no_dejan_abrir_a_todo_internet_ni_tocar_la_vm_manual(self):
        variables = leer(TF / 'variables.tf')
        self.assertIn('!startswith(ip, "0.0.0.0/")', variables)
        self.assertIn('var.grupo_recursos != "rg-lowtide"', variables)
        self.assertIn('!contains(["lowtidesec.com", "www.lowtidesec.com"], var.nombre_publico)', variables)

    def test_3_el_grupo_cubre_la_subred_y_la_tarjeta_de_red(self):
        main = leer(TF / 'main.tf')
        self.assertIn('resource "azurerm_subnet_network_security_group_association"', main)
        self.assertIn('resource "azurerm_network_interface_security_group_association"', main)


class SinSecretos(unittest.TestCase):
    def test_1_terraform_no_lee_ni_crea_secretos(self):
        # Un data azurerm_key_vault_secret o un random_password guardan el valor en terraform.tfstate.
        tf = todo_el_terraform()
        for prohibido in ('azurerm_key_vault_secret', 'random_password', 'admin_password', 'TUNNEL_TOKEN'):
            self.assertNotIn(prohibido, tf)
        self.assertIn('disable_password_authentication = true', tf)
        self.assertIn('encryption_at_host_enabled = var.cifrado_en_host', tf)

    @unittest.skipUnless(shutil.which('git') and (RAIZ / '.git').exists(), 'pide git y el repo')
    def test_2_estado_y_variables_fuera_de_git(self):
        def ignorado(ruta):
            return subprocess.run(['git', 'check-ignore', '-q', ruta], cwd=RAIZ).returncode == 0

        for ruta in ('terraform.tfstate', 'terraform.tfstate.backup', 'terraform.tfvars', 'plan.tfplan',
                     '.terraform/providers/x'):
            self.assertTrue(ignorado('infra/terraform/' + ruta), ruta)
        for ruta in ('terraform.tfvars.example', '.terraform.lock.hcl', 'main.tf'):
            self.assertFalse(ignorado('infra/terraform/' + ruta), ruta)


class CloudInit(unittest.TestCase):
    def test_1_la_regla_de_imds_es_la_de_docs_despliegue(self):
        docs = leer(RAIZ / 'docs' / 'despliegue.md')
        unidad_docs = re.search(r"lowtide-imds\.service >/dev/null <<'EOF'\n(.*?)\nEOF", docs, re.S).group(1)
        self.assertEqual(archivo_de_cloud_init('/etc/systemd/system/lowtide-imds.service').strip(),
                         unidad_docs.strip())

    def test_2_la_ip_de_la_regla_es_la_de_la_api_en_el_compose(self):
        compose = leer(RAIZ / 'docker-compose.despliegue.yml')
        ip_api = re.search(r'^  api:\n(?:    .*\n|\n)*?        ipv4_address: ([\d.]+)', compose, re.M).group(1)
        for ruta in ('/etc/systemd/system/lowtide-imds.service', '/usr/local/sbin/lowtide-arranque'):
            self.assertIn('! -s ' + ip_api + '/32 -j DROP', archivo_de_cloud_init(ruta), ruta)

    def test_3_la_regla_va_antes_que_docker(self):
        runcmd = leer(CLOUD_INIT).split('\nruncmd:\n', 1)[1]
        self.assertLess(runcmd.index('enable --now lowtide-imds.service'), runcmd.index('apt-get install'))
        self.assertLess(runcmd.index('apt-get install'), runcmd.index('lowtide-arranque.service'))

    def test_4_sin_tunel_no_se_levanta_cloudflared(self):
        arranque = archivo_de_cloud_init('/usr/local/sbin/lowtide-arranque')
        servicios = re.search(r'^servicios="([^"]+)"', arranque, re.M).group(1).split()
        compose = leer(RAIZ / 'docker-compose.yml') + leer(RAIZ / 'docker-compose.despliegue.yml')
        definidos = set(re.findall(r'^  ([a-z][a-z0-9-]*):\n', compose, re.M))
        self.assertTrue(set(servicios) <= definidos, set(servicios) - definidos)
        self.assertNotIn('cloudflared', servicios)
        self.assertIn("grep -qx 'TUNNEL_TOKEN=sin-tunel' .env", arranque)

    def test_5_la_plantilla_solo_usa_las_variables_de_main_tf(self):
        usadas = set(re.findall(r'\$\{([a-z_]+)\}', leer(CLOUD_INIT)))
        pasadas = re.search(r'templatefile\("\$\{path\.module\}/cloud-init\.yaml\.tftpl", \{(.*?)\}\)',
                            leer(TF / 'main.tf'), re.S).group(1)
        self.assertEqual(usadas, set(re.findall(r'^\s*([a-z_]+)\s*=', pasadas, re.M)))
        self.assertNotIn('%{', leer(CLOUD_INIT))


class EnvDeLaVm(unittest.TestCase):
    """Corre lowtide-env (el script que arma el .env en la VM) en una carpeta temporal, sin túnel."""

    def setUp(self):
        self.carpeta = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.carpeta)
        shutil.copy(RAIZ / '.env.example', self.carpeta / '.env.example')
        script = con_variables(archivo_de_cloud_init('/usr/local/sbin/lowtide-env'),
                               nombre_publico='iac.lowtidesec.com', tunel_secreto_url='')
        script = script.replace("CARPETA = '/opt/lowtide/BackKL'", 'CARPETA = ' + repr(str(self.carpeta)))
        self.script = self.carpeta / 'lowtide-env.py'
        self.script.write_text(script, encoding='utf-8')

    def correr(self):
        return subprocess.run([sys.executable, '-I', str(self.script)], capture_output=True, text=True, timeout=30)

    def test_1_arma_el_env_sin_valores_de_ejemplo(self):
        salida = self.correr()
        self.assertEqual(salida.returncode, 0, salida.stderr)
        env = leer(self.carpeta / '.env')
        valores = dict(linea.split('=', 1) for linea in env.splitlines() if linea and not linea.startswith('#') and '=' in linea)
        self.assertNotIn('cambia_esta_clave', env)
        self.assertNotIn('genera_tu_llave', env)
        for nombre in ('POSTGRES_PASSWORD', 'CIRDAN_APP_PASSWORD', 'VALKEY_PASSWORD'):
            self.assertEqual(len(valores[nombre]), 32, nombre)
        for nombre in ('TOTP_ENCRYPTION_KEY', 'PASSWORD_HASH_ENCRYPTION_KEY'):
            self.assertEqual(len(valores[nombre]), 44, nombre)
        self.assertNotEqual(valores['TOTP_ENCRYPTION_KEY'], valores['PASSWORD_HASH_ENCRYPTION_KEY'])
        self.assertEqual(valores['COOKIE_SECURE'], 'true')
        self.assertEqual(valores['ALLOWED_ORIGINS'], 'https://iac.lowtidesec.com')
        self.assertEqual(valores['COMPOSE_FILE'], 'docker-compose.yml:docker-compose.despliegue.yml')
        self.assertEqual(valores['TUNNEL_TOKEN'], 'sin-tunel')
        self.assertEqual(valores['DEMO_ACCOUNTS'], 'false')
        if os.name == 'posix':
            self.assertEqual((self.carpeta / '.env').stat().st_mode & 0o777, 0o600)

    def test_2_no_cambia_un_env_que_ya_existe(self):
        self.assertEqual(self.correr().returncode, 0)
        antes = leer(self.carpeta / '.env')
        salida = self.correr()
        self.assertEqual(salida.returncode, 0, salida.stderr)
        self.assertEqual(leer(self.carpeta / '.env'), antes)


if __name__ == '__main__':
    unittest.main()

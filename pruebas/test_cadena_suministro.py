"""Pruebas de la cadena de suministro de las imágenes (#82, RC-117), sin red.

Revisan lo que pide el Hecho cuando:
- .github/workflows/imagenes.yml: Trivy frena con críticas, Syft saca el SBOM y cosign firma por digest.
- La firma, la subida y los permisos de escritura solo aplican en un push, nunca en un PR.
- infra/verificar_imagenes.sh rechaza imágenes por etiqueta y no levanta nada si cosign no verifica. Se prueba con un
  docker falso que anota lo que le piden.
- docker-compose.imagenes.yml cambia las imágenes compiladas por las firmadas (`docker compose config`; sin docker
  en el PATH esa parte se salta).

    python -m unittest -v pruebas/test_cadena_suministro.py
"""
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from pruebas.test_despliegue import ARCHIVOS, ENV_FALSO, _config

RAIZ = Path(__file__).resolve().parents[1]
FLUJO = RAIZ / '.github' / 'workflows' / 'imagenes.yml'
SCRIPT = RAIZ / 'infra' / 'verificar_imagenes.sh'
API = 'ghcr.io/kernel-loco/backkl@sha256:' + 'a' * 64
PORTAL = 'ghcr.io/kernel-loco/frontkl@sha256:' + 'b' * 64


def paso(texto, nombre):
    inicio = texto.index('- name: ' + nombre)
    fin = texto.find('- name:', inicio + 1)
    return texto[inicio:fin if fin != -1 else len(texto)]


class Flujo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texto = FLUJO.read_text(encoding='utf-8')

    def test_1_trivy_frena_con_criticas_en_la_api_y_en_las_de_terceros(self):
        frena = paso(self.texto, 'Trivy frena con vulnerabilidades críticas')
        for opcion in ('--severity CRITICAL', '--exit-code 1', 'lowtide-api:ci'):
            self.assertIn(opcion, frena)
        terceros = paso(self.texto, 'Trivy frena con críticas en las imágenes de terceros')
        self.assertIn('--exit-code 1', terceros)
        self.assertIn('docker-compose.yml docker-compose.despliegue.yml', terceros)
        self.assertIn('exit "$falla"', terceros)

    def test_1b_cada_excepcion_de_trivy_vence_y_dice_por_que(self):
        excepciones = (RAIZ / '.trivyignore.yaml').read_text(encoding='utf-8').split('\n  - id: ')[1:]
        self.assertTrue(excepciones)
        for e in excepciones:
            self.assertRegex(e, r'\n    statement: \S', e[:40])
            vence = re.search(r'\n    expired_at: (\d{4}-\d{2}-\d{2})', e)
            self.assertIsNotNone(vence, e[:40])
            self.assertLessEqual(vence.group(1), '2027-01-31', 'una excepción no dura más que el reto')
        for nombre in ('Trivy frena con vulnerabilidades críticas', 'Trivy frena con críticas en las imágenes de terceros'):
            self.assertIn('--ignorefile /trivyignore.yaml', paso(self.texto, nombre), nombre)

    def test_2_sbom_con_syft_en_spdx(self):
        sbom = paso(self.texto, 'SBOM con Syft')
        self.assertIn('-o spdx-json=', sbom)
        self.assertIn('test -s sbom/backkl.spdx.json', sbom)

    def test_3_firma_solo_en_push_y_por_digest(self):
        firma = paso(self.texto, 'Subir a ghcr.io, firmar y atestar el SBOM')
        self.assertIn("if: github.event_name == 'push'", firma)
        self.assertIn('imagetools inspect "$IMAGEN:$GITHUB_SHA"', firma)
        self.assertIn('digest="$IMAGEN@$sha"', firma)
        self.assertNotIn('RepoDigests', firma)
        self.assertIn('cosign sign --yes "$digest"', firma)
        self.assertIn('cosign attest --yes --type spdxjson', firma)
        self.assertIn('cosign verify', firma)
        # El único paso que usa el token o sube algo es el de la firma.
        for otro in re.split(r'\n      - ', self.texto):
            if 'Subir a ghcr.io' not in otro:
                self.assertNotIn('docker push', otro)
                self.assertNotIn('GITHUB_TOKEN', otro)

    def test_4_permisos_de_escritura_solo_en_el_job_de_la_api(self):
        globales = self.texto.split('\njobs:\n', 1)[0]
        self.assertIn('permissions:\n  contents: read\n', globales)
        self.assertNotIn('write', globales.split('permissions:', 1)[1].split('\n\n', 1)[0])
        self.assertEqual(self.texto.count('packages: write'), 1)
        self.assertEqual(self.texto.count('id-token: write'), 1)

    def test_5_herramientas_con_version_fija(self):
        for nombre in ('TRIVY', 'SYFT', 'COSIGN'):
            imagen = re.search(r'^  %s: (\S+)$' % nombre, self.texto, re.M).group(1)
            self.assertRegex(imagen, r':v?\d+\.\d+\.\d+$', nombre)
        self.assertIn(re.search(r'^  COSIGN: (\S+)$', self.texto, re.M).group(1), SCRIPT.read_text(encoding='utf-8'))


class Verificacion(unittest.TestCase):
    """Corre infra/verificar_imagenes.sh con un docker falso en el PATH."""

    def setUp(self):
        if not shutil.which('bash'):
            self.skipTest('pide bash')
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.registro = self.tmp / 'docker.log'
        falso = self.tmp / 'docker'
        falso.write_text('#!/bin/sh\necho "$*" >> "%s"\nexit "${DOCKER_FALSO_SALIDA:-0}"\n' % self.registro,
                         encoding='utf-8')
        falso.chmod(falso.stat().st_mode | stat.S_IXUSR)

    def correr(self, *args, salida_docker=0, **imagenes):
        env = {k: v for k, v in os.environ.items() if not k.startswith(('LOWTIDE_', 'COSIGN_'))}
        env.update(imagenes, PATH=str(self.tmp) + os.pathsep + env.get('PATH', ''),
                   DOCKER_FALSO_SALIDA=str(salida_docker))
        return subprocess.run(['bash', str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=30)

    def llamadas(self):
        return self.registro.read_text(encoding='utf-8').splitlines() if self.registro.exists() else []

    def test_1_con_firma_valida_verifica_firma_y_sbom_de_las_dos(self):
        r = self.correr(LOWTIDE_API_IMAGEN=API, LOWTIDE_PORTAL_IMAGEN=PORTAL)
        self.assertEqual(r.returncode, 0, r.stderr)
        llamadas = self.llamadas()
        self.assertEqual(len(llamadas), 4)
        for repo, imagen in (('BackKL', API), ('FrontKL', PORTAL)):
            de_esta = [l for l in llamadas if l.endswith(imagen)]
            self.assertEqual(len(de_esta), 2, repo)
            self.assertTrue(any(' verify --certificate-oidc-issuer ' in l for l in de_esta), repo)
            self.assertTrue(any(' verify-attestation --type spdxjson ' in l for l in de_esta), repo)
            for l in de_esta:
                self.assertIn('https://token.actions.githubusercontent.com', l)
                self.assertIn('Kernel-Loco/%s/\\.github/workflows/imagenes\\.yml@refs/heads/(main|dev)$' % repo, l)
        self.assertFalse(any('compose' in l for l in llamadas))

    def test_2_por_etiqueta_no_pasa_ni_llama_a_cosign(self):
        for api in ('ghcr.io/kernel-loco/backkl:main', 'ghcr.io/otro/backkl@sha256:' + 'a' * 64, ''):
            r = self.correr('--levantar', LOWTIDE_API_IMAGEN=api, LOWTIDE_PORTAL_IMAGEN=PORTAL)
            self.assertNotEqual(r.returncode, 0, api)
            self.assertIn('no se levanta nada', r.stderr)
            self.assertFalse(any(API[:30] in l or 'compose' in l for l in self.llamadas()), api)

    def test_3_si_cosign_falla_no_se_levanta_nada(self):
        r = self.correr('--levantar', salida_docker=1, LOWTIDE_API_IMAGEN=API, LOWTIDE_PORTAL_IMAGEN=PORTAL)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('no se levanta nada', r.stderr)
        self.assertFalse(any('compose' in l for l in self.llamadas()))

    def test_4_con_levantar_baja_y_levanta_sin_compilar(self):
        r = self.correr('--levantar', LOWTIDE_API_IMAGEN=API, LOWTIDE_PORTAL_IMAGEN=PORTAL)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.llamadas()[-2:], ['compose pull api demo-accounts portal', 'compose up -d --no-build'])


@unittest.skipUnless(shutil.which('docker'), 'sin docker en el PATH')
class ComposeConImagenes(unittest.TestCase):
    def test_1_api_demo_y_portal_usan_la_imagen_firmada_sin_compilar(self):
        # Con el profile del programador (RC-52), que en la VM va en COMPOSE_PROFILES: sin él compilaría sin firma.
        env = dict(ENV_FALSO, LOWTIDE_API_IMAGEN=API, LOWTIDE_PORTAL_IMAGEN=PORTAL)
        rc, salida = _config(env, archivos=ARCHIVOS + ['docker-compose.imagenes.yml'], perfiles=('programador',))
        self.assertEqual(rc, 0, salida[-500:])
        svc = json.loads(salida)['services']
        for nombre, imagen in (('api', API), ('demo-accounts', API), ('portal', PORTAL), ('programador', API)):
            self.assertEqual(svc[nombre]['image'], imagen, nombre)
            self.assertNotIn('build', svc[nombre], nombre)
            self.assertEqual(svc[nombre]['pull_policy'], 'missing', nombre)
        # Lo demás del despliegue sigue igual.
        self.assertEqual(svc['api']['networks']['default']['ipv4_address'], '10.249.93.20')
        self.assertEqual(svc['api'].get('ports', []), [])

    def test_2_sin_las_imagenes_no_arranca(self):
        # Compose nombra solo la primera variable que le falta y el orden no es fijo, así que cada subprueba pone una
        # sola imagen y exige el mensaje de la otra, el texto del :? de docker-compose.imagenes.yml.
        for falta, puesta in (('LOWTIDE_API_IMAGEN', {'LOWTIDE_PORTAL_IMAGEN': PORTAL}),
                              ('LOWTIDE_PORTAL_IMAGEN', {'LOWTIDE_API_IMAGEN': API}), (None, {})):
            with self.subTest(falta=falta or 'las dos'):
                rc, salida = _config(dict(ENV_FALSO, **puesta), archivos=ARCHIVOS + ['docker-compose.imagenes.yml'])
                self.assertNotEqual(rc, 0, salida[-500:])
                if falta:
                    self.assertIn('Falta %s en .env' % falta, salida)
                else:
                    self.assertRegex(salida, r'Falta LOWTIDE_(API|PORTAL)_IMAGEN en \.env')


if __name__ == '__main__':
    unittest.main()

"""Integración del respaldo completo de cartas, su llave y la base (RC-28, RC-339)."""
import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import uuid
from pathlib import Path

from pruebas.pila import exigir_contenedor

RAIZ = Path(__file__).resolve().parents[1]
RESPALDO = RAIZ / 'db' / 'respaldo'
PDF = b'%PDF-1.4\nCIRDAN_TEST_CARTA\n%%EOF\n'
# Empresa y usuario de db/semillas/001_datos_demo.sql. Los dos dominios los crea la prueba y no tienen carta de semilla:
# desde la 036 (RC-272) una carta nueva revoca la anterior del dominio y deja authorization.superseded en audit_log,
# que no se borra. DOMINIO_MANO lleva una carta subida a mano (AAD con el domain_id) y DOMINIO_MIFIEL una que salió de
# la API de Mifiel (AAD con el id de la solicitud, migración 031).
ORG_ID = '20000000-0000-4000-8000-000000000001'
USER_ID = '30000000-0000-4000-8000-000000000001'
DOMINIO_MANO = '40000000-0000-4000-8000-0000000272a1'
DOMINIO_MIFIEL = '40000000-0000-4000-8000-0000000272a2'
FQDN_MANO = 'respaldo-mano.acme-demo.mx'
FQDN_MIFIEL = 'respaldo-mifiel.acme-demo.mx'
# Cómo registra el portal cada carta (cirdan/api/firmas.py). %(...)s solo recibe uuid y hex generados por la prueba.
SQL_REGISTRO = """
BEGIN;
INSERT INTO domains (id, organization_id, fqdn, status, txt_token, added_by) VALUES
  ('%(mano)s', '%(org)s', '%(fqdn_mano)s', 'pending_verification', '%(tok_mano)s', '%(usuario)s'),
  ('%(dominio)s', '%(org)s', '%(fqdn)s', 'pending_verification', '%(tok_mifiel)s', '%(usuario)s');
INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, signer_email,
  signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, template_version, activities,
  signature_provider, evidence_key, evidence_sha256)
VALUES ('%(org)s', '%(mano)s', 'Prueba', 'Cargo', 'prueba@example.com', '%(k_mano_pdf)s',
  decode('%(h_mano_pdf)s', 'hex'), '2026-01-01', '2027-01-01', '%(usuario)s', 1, '{1,2}', 'mifiel',
  '%(k_mano_xml)s', decode('%(h_mano_xml)s', 'hex'));
INSERT INTO signature_requests (id, organization_id, provider, environment, fqdn, signer_name, signer_title,
  signer_email, valid_from, valid_until, template_version, activities, unsigned_document_key, unsigned_sha256,
  requested_by)
VALUES ('%(sol)s', '%(org)s', 'mifiel', 'production', '%(fqdn)s', 'Prueba', 'Cargo', 'prueba@example.com',
  '2026-01-01', '2027-01-01', 1, '{1,2}', '%(k_sin_firma)s', decode('%(h_sin_firma)s', 'hex'), '%(usuario)s');
UPDATE signature_requests SET status = 'sent', provider_document_id = '%(doc)s' WHERE id = '%(sol)s';
UPDATE signature_requests SET status = 'signed', signed_document_key = '%(k_firmado)s',
  signed_sha256 = decode('%(h_firmado)s', 'hex'), evidence_key = '%(k_evidencia)s',
  evidence_sha256 = decode('%(h_evidencia)s', 'hex'), provider_signed_at = '2026-01-02T00:00:00Z'
 WHERE id = '%(sol)s';
INSERT INTO domain_authorizations (organization_id, domain_id, signer_name, signer_title, signer_email,
  signed_document_key, signed_document_sha256, valid_from, valid_until, accepted_by, template_version, activities,
  signature_request_id, signature_provider, evidence_key, evidence_sha256, signed_at)
SELECT organization_id, '%(dominio)s', signer_name, signer_title, signer_email, signed_document_key, signed_sha256,
       valid_from, valid_until, '%(usuario)s', template_version, activities, id, provider, evidence_key,
       evidence_sha256, provider_signed_at
  FROM signature_requests WHERE id = '%(sol)s';
UPDATE signature_requests SET status = 'accepted', decided_by = '%(usuario)s', decided_at = now()
 WHERE id = '%(sol)s';
COMMIT;
"""
# Las tablas de cartas no se borran (sus guardias). Solo para limpiar la prueba se apagan los disparadores en la sesión.
SQL_LIMPIEZA = """
BEGIN;
SET LOCAL session_replication_role = replica;
DELETE FROM domain_authorizations WHERE signed_document_key IN ('%(k_mano_pdf)s', '%(k_firmado)s');
DELETE FROM signature_requests WHERE id = '%(sol)s';
DELETE FROM domains WHERE id IN ('%(mano)s', '%(dominio)s');
COMMIT;
"""
CONTENEDOR_BASE = (os.environ.get('RESPALDO_CONTENEDOR') or '').strip() or (
    'cirdan-pg16' if (os.environ.get('CI') or '').strip().lower() in ('true', '1') else None)
CONTENEDOR_CARTAS = (os.environ.get('RESPALDO_CARTAS_CONTENEDOR') or '').strip() or (
    'cirdan-api' if (os.environ.get('CI') or '').strip().lower() in ('true', '1') else None)
PATRON = re.compile(r'^cirdan_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}\.backup\.age$')


def correr(argumentos, env=None, entrada=None):
    return subprocess.run(argumentos, input=entrada, capture_output=True, text=True, encoding='utf-8',
                          errors='replace', env={**os.environ, **(env or {})})


class PaqueteSeguro(unittest.TestCase):
    def test_solo_extrae_los_archivos_cifrados_esperados(self):
        with tempfile.TemporaryDirectory() as temporal:
            raiz = Path(temporal)
            archivo = raiz / 'paquete.tar'
            salida = raiz / 'salida'
            salida.mkdir(mode=0o700)
            with tarfile.open(archivo, 'w') as tar:
                for nombre in ('cirdan.dump.age', 'cartas.tar.age', 'carta.key.age'):
                    datos = (nombre + '-cifrado').encode()
                    info = tarfile.TarInfo(nombre)
                    info.size = len(datos)
                    tar.addfile(info, io.BytesIO(datos))

            resultado = correr(['python', str(RESPALDO / 'paquete.py'), 'extraer', str(archivo), str(salida)])

            self.assertEqual(resultado.returncode, 0, resultado.stderr)
            self.assertEqual({ruta.name for ruta in salida.iterdir()},
                             {'cirdan.dump.age', 'cartas.tar.age', 'carta.key.age'})
            if os.name != 'nt':
                self.assertTrue(all(ruta.stat().st_mode & 0o777 == 0o600 for ruta in salida.iterdir()))

    def test_rechaza_rutas_y_enlaces_en_el_archivo_de_cartas(self):
        with tempfile.TemporaryDirectory() as temporal:
            raiz = Path(temporal)
            archivo = raiz / 'cartas.tar'
            salida = raiz / 'cartas'
            salida.mkdir(mode=0o700)
            with tarfile.open(archivo, 'w') as tar:
                info = tarfile.TarInfo('../fuera.lt1')
                info.size = 31
                tar.addfile(info, io.BytesIO(b'LT1' + b'x' * 28))
            resultado = correr(['python', str(RESPALDO / 'paquete.py'), 'cartas', str(archivo), str(salida)])
            self.assertNotEqual(resultado.returncode, 0)
            self.assertFalse((raiz / 'fuera.lt1').exists())

            archivo_enlace = raiz / 'enlace.tar'
            with tarfile.open(archivo_enlace, 'w') as tar:
                info = tarfile.TarInfo('a' * 32 + '.lt1')
                info.type = tarfile.SYMTYPE
                info.linkname = '../fuera.lt1'
                tar.addfile(info)
            resultado = correr(['python', str(RESPALDO / 'paquete.py'), 'cartas',
                                str(archivo_enlace), str(salida)])
            self.assertNotEqual(resultado.returncode, 0)
            self.assertFalse((raiz / 'fuera.lt1').exists())

    def test_valida_llave_base64_url_safe_de_32_bytes(self):
        with tempfile.TemporaryDirectory() as temporal:
            llave = Path(temporal) / 'llave'
            llave.write_text(base64.urlsafe_b64encode(b'k' * 32).decode('ascii'), encoding='ascii')
            bien = correr(['python', str(RESPALDO / 'paquete.py'), 'llave', str(llave)])
            self.assertEqual(bien.returncode, 0, bien.stderr)
            llave.write_text(base64.urlsafe_b64encode(b'k' * 31).decode('ascii'), encoding='ascii')
            mal = correr(['python', str(RESPALDO / 'paquete.py'), 'llave', str(llave)])
            self.assertNotEqual(mal.returncode, 0)

    def test_tope_por_carta_cubre_lo_que_baja_mifiel(self):
        texto = (RESPALDO / 'paquete.py').read_text(encoding='utf-8')
        self.assertIn('MAX_CARTA = 25 * 1024 * 1024 + 31', texto)
        self.assertIn('<= 25 * 1024 * 1024 + 31', (RESPALDO / 'respaldar.sh').read_text(encoding='utf-8'))
        self.assertIn('TOPE_ARCHIVO = 25 * 1024 * 1024',
                      (RAIZ / 'cirdan' / 'firma' / 'mifiel.py').read_text(encoding='utf-8'))


try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # el runner del CI puede no traerla; dentro de la imagen sí está
    AESGCM = None


@unittest.skipUnless(AESGCM, 'falta cryptography')
class VerificarCartas(unittest.TestCase):
    """verificar_cartas.py con referencias como las arma restaurar_completo.sh, sin Docker."""

    def setUp(self):
        self.raiz = Path(tempfile.mkdtemp(prefix='verificar_cartas_'))
        self.addCleanup(shutil.rmtree, self.raiz, True)
        self.clave = os.urandom(32)
        (self.raiz / 'llave').write_text(base64.urlsafe_b64encode(self.clave).decode('ascii') + '\n', encoding='ascii')
        self.cartas = self.raiz / 'cartas'
        self.cartas.mkdir()

    def _carta(self, datos, id_aad):
        nombre = uuid.uuid4().hex + '.lt1'
        nonce = os.urandom(12)
        aad = ('%s:%s:%s' % (ORG_ID, id_aad, nombre)).encode()
        (self.cartas / nombre).write_bytes(b'LT1' + nonce + AESGCM(self.clave).encrypt(nonce, datos, aad))
        return nombre, hashlib.sha256(datos).hexdigest()

    def _verificar(self, filas):
        (self.raiz / 'referencias.tsv').write_text(''.join(f + '\n' for f in filas), encoding='ascii')
        return correr(['python', str(RESPALDO / 'verificar_cartas.py'), str(self.raiz / 'llave'),
                       str(self.raiz / 'referencias.tsv'), str(self.cartas)])

    def test_aad_de_solicitud_y_de_dominio_con_duplicados_y_semillas(self):
        solicitud = str(uuid.uuid4())
        mano, h_mano = self._carta(PDF, DOMINIO_MANO)
        firmada, h_firmada = self._carta(PDF + b'firmado', solicitud)
        filas = ['%s|%s|%s|%s' % (ORG_ID, DOMINIO_MANO, mano, h_mano),
                 '%s|%s|%s|%s' % (ORG_ID, solicitud, firmada, h_firmada),
                 '%s|%s|%s|%s' % (ORG_ID, solicitud, firmada, h_firmada),
                 '%s|%s|authorizations/acme-demo/acme-demo.mx_2026.pdf|%s' % (ORG_ID, DOMINIO_MANO, 'ab' * 32)]
        bien = self._verificar(filas)
        self.assertEqual(bien.returncode, 0, bien.stderr)
        self.assertIn('2 cartas referenciadas verificadas', bien.stdout)
        self.assertIn('1 llaves sin archivo (anteriores al alta)', bien.stdout)

        con_dominio = self._verificar(['%s|%s|%s|%s' % (ORG_ID, DOMINIO_MIFIEL, firmada, h_firmada)])
        self.assertNotEqual(con_dominio.returncode, 0)
        self.assertIn('no autentica', con_dominio.stderr)

        distintas = self._verificar(filas[1:2] + ['%s|%s|%s|%s' % (ORG_ID, solicitud, firmada, h_mano)])
        self.assertNotEqual(distintas.returncode, 0)
        self.assertIn('datos distintos', distintas.stderr)

        # test_5 de test_escaneos_api.py deja la llave de una semilla con el sufijo .prueba: sigue sin archivo.
        semilla = 'authorizations/acme-demo/acme-demo.mx_2026.pdf.prueba'
        sin_archivo = self._verificar(['%s|%s|%s|' % (ORG_ID, DOMINIO_MANO, semilla)])
        self.assertEqual(sin_archivo.returncode, 0, sin_archivo.stderr)

        for llave in ('CIRDAN_FAKE_carta', 'authorizations/../fuera.pdf'):
            with self.subTest(llave=llave):
                mala = self._verificar(['%s|%s|%s|%s' % (ORG_ID, DOMINIO_MANO, llave, h_mano)])
                self.assertNotEqual(mala.returncode, 0)
                self.assertIn('referencia de carta no es', mala.stderr)


@unittest.skipUnless(os.name != 'nt' and shutil.which('bash') and shutil.which('findmnt'),
                     'necesita bash y findmnt')
class TemporalEnTmpfs(unittest.TestCase):
    def test_respaldar_y_restaurar_usan_el_tmpfs_escribible(self):
        temporal = '/run' if os.access('/run', os.W_OK) else '/run/lock'
        if not os.access(temporal, os.W_OK):
            self.skipTest('no hay carpeta temporal escribible en /run')
        tipo = subprocess.run(['findmnt', '-n', '-o', 'FSTYPE', '--target', temporal],
                              capture_output=True, text=True, check=True).stdout.strip()
        if tipo != 'tmpfs':
            self.skipTest('la carpeta temporal no está en tmpfs')

        with tempfile.TemporaryDirectory() as tmp:
            raiz = Path(tmp)
            binarios = raiz / 'bin'
            binarios.mkdir()
            for nombre in ('age', 'az', 'docker'):
                (binarios / nombre).symlink_to('/bin/false')
            registro = raiz / 'mktemp'
            mktemp = binarios / 'mktemp'
            mktemp.write_text('#!/bin/sh\nprintf "%s" "$2" > "$REGISTRO_MKTEMP"\nexit 1\n', encoding='ascii')
            mktemp.chmod(0o755)
            conf = raiz / 'respaldo.conf'
            conf.write_text('CARPETA=%s\nRECEPTOR_AGE=age1%s\nSUBIR=0\n' % (raiz / 'salida', 'q' * 58),
                            encoding='ascii')
            conf.chmod(0o600)
            identidad = raiz / 'identidad'
            identidad.touch()
            paquete = raiz / 'prueba.backup.age'
            paquete.touch()
            env = {'PATH': str(binarios) + os.pathsep + os.environ.get('PATH', ''),
                   'REGISTRO_MKTEMP': str(registro), 'RESPALDO_CONF': str(conf),
                   'AGE_IDENTIDAD': str(identidad)}
            comandos = (
                ['bash', str(RESPALDO / 'respaldar.sh')],
                ['bash', str(RESPALDO / 'restaurar.sh'), str(paquete), 'db', 'nueva'],
                ['bash', str(RESPALDO / 'restaurar_completo.sh'), str(paquete), 'db', 'api',
                 'nueva', 'volumen', 'boveda', 'secreto'],
            )
            for comando in comandos:
                with self.subTest(script=comando[1]):
                    registro.unlink(missing_ok=True)
                    resultado = correr(comando, env=env)
                    self.assertNotEqual(resultado.returncode, 0)
                    self.assertTrue(registro.exists(), resultado.stderr)
                    self.assertTrue(registro.read_text().startswith(temporal + '/lowtide-'))

            findmnt = binarios / 'findmnt'
            findmnt.write_text('#!/bin/sh\nprintf "ext4\\n"\n', encoding='ascii')
            findmnt.chmod(0o755)
            for comando in comandos:
                with self.subTest(script=comando[1], sistema='ext4'):
                    registro.unlink(missing_ok=True)
                    resultado = correr(comando, env=env)
                    self.assertNotEqual(resultado.returncode, 0)
                    self.assertIn('debe ser tmpfs', resultado.stderr)
                    self.assertFalse(registro.exists())


@unittest.skipUnless(shutil.which('bash') and shutil.which('age') and shutil.which('docker'),
                     'faltan bash, age o docker')
@unittest.skipUnless(CONTENEDOR_BASE and CONTENEDOR_CARTAS,
                     'fuera del CI hay que nombrar una base y API de una pila aislada')
class RespaldoCartas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        exigir_contenedor(CONTENEDOR_BASE)
        exigir_contenedor(CONTENEDOR_CARTAS)
        cls.temporal = Path(tempfile.mkdtemp(prefix='respaldo_cartas_'))
        cls.db = 'cirdan_prueba_cartas_%d' % os.getpid()
        cls.volumen = 'prueba-cartas-%d' % os.getpid()
        cls.llave_age = cls.temporal / 'age.txt'
        subprocess.run(['age-keygen', '-o', str(cls.llave_age)], check=True, capture_output=True)
        cls.identidad = cls.llave_age.read_text(encoding='ascii')
        cls.publica = subprocess.run(['age-keygen', '-y', str(cls.llave_age)], check=True, capture_output=True,
                                     text=True, encoding='ascii').stdout.strip()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'volumen'):
            subprocess.run(['docker', 'volume', 'rm', cls.volumen], capture_output=True, check=False)
        shutil.rmtree(cls.temporal, ignore_errors=True)
        if hasattr(cls, 'db') and CONTENEDOR_BASE:
            exigir_contenedor(CONTENEDOR_BASE)
            subprocess.run(
                ['docker', 'exec', CONTENEDOR_BASE, 'sh', '-c',
                 'psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 -c \'DROP DATABASE IF EXISTS "%s"\'' % cls.db],
                capture_output=True, check=False)

    def _carta_en_api(self, codigo):
        exigir_contenedor(CONTENEDOR_CARTAS)
        return correr(['docker', 'exec', CONTENEDOR_CARTAS, 'python', '-c', codigo])

    def _conteos(self, base):
        exigir_contenedor(CONTENEDOR_BASE)
        return subprocess.run(
            ['docker', 'exec', '-i', '-e', 'BASE=' + base, CONTENEDOR_BASE, 'sh', '-c',
             'exec psql -U "$POSTGRES_USER" -d "$BASE" -X -q -At -v ON_ERROR_STOP=1'],
            input=(RAIZ / 'db' / 'respaldo' / 'conteos.sql').read_text(encoding='utf-8'),
            capture_output=True, text=True, encoding='utf-8', check=True).stdout.strip()

    def _sql(self, base, texto):
        exigir_contenedor(CONTENEDOR_BASE)
        return subprocess.run(
            ['docker', 'exec', '-i', '-e', 'BASE=' + base, CONTENEDOR_BASE, 'sh', '-c',
             'exec psql -U "$POSTGRES_USER" -d "$BASE" -X -q -At -v ON_ERROR_STOP=1'],
            input=texto, capture_output=True, text=True, encoding='utf-8')

    def _registrar_cartas(self):
        """Guarda cinco archivos en el volumen de la API y los registra en la base como lo hace el portal."""
        solicitud = str(uuid.uuid4())
        documentos = {
            'mano_pdf': (PDF, DOMINIO_MANO), 'mano_xml': (b'<xml>CIRDAN_TEST_EVIDENCIA_A</xml>', DOMINIO_MANO),
            'sin_firma': (PDF + b'sin firma', solicitud), 'firmado': (PDF + b'firmado', solicitud),
            'evidencia': (b'<xml>CIRDAN_TEST_EVIDENCIA_B</xml>', solicitud),
        }
        codigo = ('import json; from cirdan.cartas import guardar; '
                  'print(json.dumps({k: guardar(d, %r, a)[0] for k, (d, a) in %r.items()}))' % (ORG_ID, documentos))
        guardadas = self._carta_en_api(codigo)
        self.assertEqual(guardadas.returncode, 0, guardadas.stderr)
        llaves = json.loads(guardadas.stdout)
        self.assertEqual(set(llaves), set(documentos))
        self.assertTrue(all(re.fullmatch(r'[0-9a-f]{32}\.lt1', v) for v in llaves.values()), llaves)
        self.addCleanup(self._carta_en_api,
                        'import os; [os.unlink(os.path.join(os.environ["CARTA_STORAGE_DIR"], n)) for n in %r]'
                        % sorted(llaves.values()))
        huellas = {k: hashlib.sha256(d).hexdigest() for k, (d, _) in documentos.items()}
        datos = {'org': ORG_ID, 'usuario': USER_ID, 'mano': DOMINIO_MANO, 'dominio': DOMINIO_MIFIEL,
                 'fqdn_mano': FQDN_MANO, 'fqdn': FQDN_MIFIEL, 'sol': solicitud,
                 'doc': 'CIRDAN_FAKE_doc_' + uuid.uuid4().hex,
                 'tok_mano': uuid.uuid4().hex, 'tok_mifiel': uuid.uuid4().hex}
        datos.update({'k_' + k: v for k, v in llaves.items()})
        datos.update({'h_' + k: v for k, v in huellas.items()})
        self.addCleanup(self._sql, 'cirdan', SQL_LIMPIEZA % datos)
        registro = self._sql('cirdan', SQL_REGISTRO % datos)
        self.assertEqual(registro.returncode, 0, registro.stderr)
        return llaves, huellas

    def test_respaldar_y_restaurar_base_cartas_y_llave(self):
        llaves, huellas = self._registrar_cartas()

        leer_llave = (
            'import base64, sys; from cirdan.cartas import _key; '
            'sys.stdout.write(base64.urlsafe_b64encode(_key()).decode("ascii"))'
        )
        llave_origen = self._carta_en_api(leer_llave)
        self.assertEqual(llave_origen.returncode, 0, llave_origen.stderr)
        self.assertEqual(len(base64.urlsafe_b64decode(llave_origen.stdout)), 32)

        antes = self._conteos('cirdan')
        carpeta = self.temporal / 'respaldos'
        configuracion = self.temporal / 'respaldo.conf'
        configuracion.write_text(
            'CONTENEDOR_BASE=%s\nCONTENEDOR_CARTAS=%s\nCARPETA=%s\nRECEPTOR_AGE=%s\nSUBIR=0\nRETENCION=7\n'
            % (CONTENEDOR_BASE, CONTENEDOR_CARTAS, carpeta, self.publica),
            encoding='ascii')
        configuracion.chmod(0o600)
        creado = correr(['bash', str(RESPALDO / 'respaldar.sh')],
                        env={'RESPALDO_CONF': str(configuracion)})
        self.assertEqual(creado.returncode, 0, creado.stderr)
        nombres = sorted(nombre for nombre in os.listdir(carpeta) if PATRON.fullmatch(nombre))
        self.assertEqual(len(nombres), 1, nombres)
        paquete = carpeta / nombres[0]
        self.assertTrue(paquete.read_bytes().startswith(b'age-encryption.org/v1'))
        self.assertNotIn(PDF, paquete.read_bytes())
        self.assertNotIn(llave_origen.stdout.encode('ascii'), paquete.read_bytes())

        binarios = self.temporal / 'bin'
        binarios.mkdir()
        llave_restaurada = self.temporal / 'llave-restaurada.txt'
        az_falso = binarios / 'az'
        az_falso.write_text(
            '#!/usr/bin/env python3\n'
            'import os, shutil, sys\n'
            'args = sys.argv[1:]\n'
            'shutil.copyfile(args[args.index("--file") + 1], os.environ["AZ_FAKE_KEY_OUTPUT"])\n'
            'print("https://fake-vault.vault.azure.net/secrets/carta-key/0123456789abcdef0123456789abcdef")\n',
            encoding='utf-8')
        az_falso.chmod(0o755)
        destino_path = str(binarios) + os.pathsep + os.environ.get('PATH', '')
        restaurado = correr(
            ['bash', str(RESPALDO / 'restaurar_completo.sh'), str(paquete), CONTENEDOR_BASE,
             CONTENEDOR_CARTAS, self.db, self.volumen, 'fake-vault', 'carta-key'],
            env={'AGE_IDENTIDAD': str(self.llave_age), 'PATH': destino_path,
                 'AZ_FAKE_KEY_OUTPUT': str(llave_restaurada)})
        self.assertEqual(restaurado.returncode, 0, restaurado.stderr)
        self.assertNotIn(llave_origen.stdout, restaurado.stdout + restaurado.stderr)
        self.assertEqual(llave_restaurada.read_text(encoding='ascii'), llave_origen.stdout)
        self.assertIn('CARTA_VOLUME_NAME=' + self.volumen, restaurado.stdout)
        # restaurar_completo.sh arma las referencias con la base restaurada: las cinco cartas de arriba (la firmada y
        # su evidencia salen de las dos tablas y cuentan una vez) más las que ya hubiera. Las semillas, sin archivo.
        verificadas = re.search(r'verificar_cartas: (\d+) cartas referenciadas verificadas', restaurado.stdout)
        self.assertIsNotNone(verificadas, restaurado.stdout)
        self.assertGreaterEqual(int(verificadas.group(1)), 5)
        self.assertRegex(restaurado.stdout, r'verificar_cartas: \d+ llaves sin archivo \(anteriores al alta\)')

        # Con el domain_id en lugar del id de la solicitud, la carta de Mifiel no autentica: el AAD sí se revisa.
        referencias = self.temporal / 'referencias.tsv'
        referencias.write_text('%s|%s|%s|%s\n' % (ORG_ID, DOMINIO_MIFIEL, llaves['firmado'], huellas['firmado']),
                               encoding='ascii')
        imagen = subprocess.run(['docker', 'inspect', '--format', '{{.Config.Image}}', CONTENEDOR_CARTAS],
                                check=True, capture_output=True, text=True, encoding='utf-8').stdout.strip()
        verificada = correr([
            'docker', 'run', '--rm', '--network', 'none', '--user', '0:0',
            '--cap-drop', 'ALL', '--cap-add', 'DAC_OVERRIDE', '--security-opt', 'no-new-privileges',
            '--entrypoint', 'python',
            '-v', self.volumen + ':/cartas:ro',
            '-v', str(llave_restaurada) + ':/run/carta.key:ro',
            '-v', str(referencias) + ':/run/referencias.tsv:ro',
            '-v', str(RESPALDO / 'verificar_cartas.py') + ':/run/verificar_cartas.py:ro',
            imagen, '/run/verificar_cartas.py', '/run/carta.key', '/run/referencias.tsv', '/cartas',
        ])
        self.assertNotEqual(verificada.returncode, 0)
        self.assertIn('no autentica', verificada.stderr)

        accesible = correr([
            'docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'python',
            '-v', self.volumen + ':/cartas', imagen, '-c',
            'import os, sys; assert os.access("/cartas", os.W_OK); '
            'assert all(open("/cartas/" + n, "rb").read(3) == b"LT1" for n in sys.argv[1:])',
            *sorted(llaves.values()),
        ])
        self.assertEqual(accesible.returncode, 0, accesible.stderr)

        self.assertEqual(self._conteos(self.db), antes)


if __name__ == '__main__':
    unittest.main()

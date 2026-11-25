"""Autoprueba de .gitleaks.toml (RC-254): corre el gitleaks del job de seguridad sobre un repo de casos y revisa que
marque lo que debe y salte solo lo que debe. La corre el job de seguridad antes de revisar la historia, y en tu PC:

    python pruebas/gitleaks_autoprueba.py

Los casos se arman al correr, en una carpeta temporal: ningún archivo del repo trae un token falso fuera de
pruebas/fixtures/ ni un token con forma real, así que la revisión de la historia no los ve. Solo pide git y docker,
y el contenedor corre sin red.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
# La misma imagen, fijada por digest, que el paso de gitleaks de .github/workflows/seguridad.yml
IMAGEN = 'zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46'

FALSO = 'CIRDAN_' + 'FAKE_'
GHP = 'gh' + 'p_' + 'R8vKq2LmN4pX7sT9wY3zA6bC1dE5fG0hJ2kL'   # forma de token de GitHub, no es real
HUELLA = hashlib.sha256(b'lowtide-autoprueba').hexdigest()
LLAVE = 'api' + '_key'

# (archivo, texto de la línea, regla que debe marcarla o None si debe saltarse)
CASOS = [
    ('cirdan/a.py', 'T1 = "%saaaaaaaa1111"' % FALSO, 'lowtide-token-falso-fuera-de-fixtures'),
    ('cirdan/a.py', 'T2 = "%sbbbbbbbb2222"  # activo = false' % FALSO, 'lowtide-token-falso-fuera-de-fixtures'),
    ('cirdan/a.py', 'T3 = "%sxfalsex99999"' % FALSO, 'lowtide-token-falso-fuera-de-fixtures'),
    ('cirdan/a.py', 'T4 = "%scccccccc3333"; v = null' % FALSO, 'lowtide-token-falso-fuera-de-fixtures'),
    ('cirdan/a.py', 'TOKEN = "%s"  # false' % GHP, 'github-pat'),
    ('cirdan/a.py', 'TOKEN2 = "%s"  # gitleaks:allow' % GHP, 'github-pat'),
    ('cirdan/a.py', '%s = "%s"' % (LLAVE, HUELLA), 'generic-api-key'),
    ('pruebas/test_x.py', "    'db/migraciones/016_%s_lookup.sql': '%s',  # false" % (LLAVE, HUELLA),
     'generic-api-key'),
    ('pruebas/test_x.py', "    'db/migraciones/016_%s_lookup.sql': '%s'," % (LLAVE, HUELLA), None),
    ('pruebas/test_x.py', 'T5 = "%sdddddddd4444"' % FALSO, 'lowtide-token-falso-fuera-de-fixtures'),
    ('pruebas/fixtures/tokens.py', 'T6 = "%seeeeeeee5555"' % FALSO, None),
]


def esperados():
    lineas, salida = {}, set()
    for archivo, texto, regla in CASOS:
        lineas.setdefault(archivo, []).append(texto)
        if regla:
            salida.add((archivo, len(lineas[archivo]), regla))
    return lineas, salida


def correr():
    lineas, esperado = esperados()
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        os.chmod(repo, 0o755)   # el usuario del contenedor la lee, como el checkout del job
        for archivo, textos in lineas.items():
            (repo / archivo).parent.mkdir(parents=True, exist_ok=True)
            (repo / archivo).write_bytes(('\n'.join(textos) + '\n').encode('utf-8'))
        (repo / '.gitleaks.toml').write_bytes((RAIZ / '.gitleaks.toml').read_bytes())
        git = ['git', '-C', str(repo), '-c', 'user.name=autoprueba', '-c', 'user.email=autoprueba@lowtide.invalid',
               '-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false']
        subprocess.run(git + ['init', '-q'], check=True)
        subprocess.run(git + ['add', '.'], check=True)
        subprocess.run(git + ['commit', '-q', '-m', 'casos'], check=True)
        # Mismas opciones que el paso del job, salvo .gitleaksignore, que aquí no aplica, y el reporte en JSON
        corrida = subprocess.run(
            ['docker', 'run', '--rm', '--network', 'none', '-v', '%s:/repo' % repo, IMAGEN, 'git', '/repo',
             '--config', '/repo/.gitleaks.toml', '--ignore-gitleaks-allow', '--log-opts=--full-history HEAD',
             '--redact', '--no-banner', '--report-format', 'json', '--report-path', '/dev/stdout'],
            capture_output=True, text=True, encoding='utf-8', errors='replace')
    # El reporte sale por la salida estándar y los avisos por la de error: el contenedor no escribe en la carpeta.
    # gitleaks sale con 1 si encontró algo, que aquí es lo esperado.
    if corrida.returncode not in (0, 1):
        raise SystemExit('gitleaks no corrió (salida %d):\n%s' % (corrida.returncode, corrida.stderr[-2000:]))
    reporte = json.loads(corrida.stdout)
    hallado = {(h['File'], h['StartLine'], h['RuleID']) for h in reporte}
    return esperado, hallado


def main():
    esperado, hallado = correr()
    faltan, sobran = sorted(esperado - hallado), sorted(hallado - esperado)
    for archivo, linea, regla in faltan:
        print('NO MARCÓ %s:%d (%s)' % (archivo, linea, regla))
    for archivo, linea, regla in sobran:
        print('MARCÓ DE MÁS %s:%d (%s)' % (archivo, linea, regla))
    if faltan or sobran:
        return 1
    print('gitleaks marcó los %d casos que debe y saltó los %d que debe' % (len(esperado), len(CASOS) - len(esperado)))
    return 0


if __name__ == '__main__':
    sys.exit(main())

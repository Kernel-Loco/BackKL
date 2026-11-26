"""Capa de MITRE ATT&CK Navigator con las técnicas que LowTide detecta (#58, RC-106).

El mapeo de cada regla a ATT&CK vive en la base (`scoring_rule_framework_mappings`, migraciones 011 y 012, #68 y
RC-131) y la API lo da en `frameworks.mitre_attack` de cada hallazgo. Aquí se reconstruye, sin base ni red, leyendo las
migraciones en orden: la 011 crea el mapeo, la 012 corrige técnicas con UPDATE y las siguientes agregan reglas nuevas
con su mapeo. Gana el último valor de cada regla, como en la base.

La capa colorea cada técnica por el número de reglas que la detectan y lista esas reglas en su comentario. Se importa
en https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer > Upload from local).

    python -m cirdan.navigator              # imprime la capa
    python -m cirdan.navigator --escribir   # la guarda en docs/attack_navigator_lowtide.json

pruebas/test_navigator.py revisa que el archivo guardado sea el que sale de las migraciones.
"""
import argparse
import json
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
MIGRACIONES = RAIZ / 'db' / 'migraciones'
CAPA = RAIZ / 'docs' / 'attack_navigator_lowtide.json'
TABLA = 'scoring_rule_framework_mappings'
VERSION_ATTACK = '19'

# Una fila de mapeo: ('codigo', 'Enterprise v19', 'T1234.001'|NULL, 'nombre'|NULL, ...) en los INSERT, o
# ('codigo', 'T1234.001'|NULL, 'nombre'|NULL, ...) en el UPDATE ... FROM (VALUES ...) de la 012.
_FILA = re.compile(
    r"\(\s*'(?P<regla>[a-z][a-z0-9_]*)'\s*,\s*(?:'Enterprise v\d+'\s*,\s*)?"
    r"(?:'(?P<tecnica>T\d{4}(?:\.\d{3})?)'\s*,\s*'(?P<nombre>(?:[^']|'')*)'|NULL\s*,\s*NULL)")


def _sentencias(sql):
    """Las sentencias del archivo, sin comentarios '--'. Un ';' o un '--' dentro de un texto no cuentan, y un
    apóstrofo dentro de un comentario no abre un texto."""
    partes, actual, en_texto, i = [], [], False, 0
    while i < len(sql):
        caracter = sql[i]
        if not en_texto and sql.startswith('--', i):
            fin = sql.find('\n', i)
            i = len(sql) if fin == -1 else fin
            continue
        if caracter == "'":
            en_texto = not en_texto   # '' dentro de un texto cierra y abre: el texto sigue
        if caracter == ';' and not en_texto:
            partes.append(''.join(actual))
            actual = []
        else:
            actual.append(caracter)
        i += 1
    partes.append(''.join(actual))
    return partes


def mapeo(carpeta=MIGRACIONES):
    """{regla: (técnica, nombre) o None} después de aplicar todas las migraciones en orden."""
    resultado = {}
    for archivo in sorted(carpeta.glob('[0-9][0-9][0-9]_*.sql')):
        for sentencia in _sentencias(archivo.read_text(encoding='utf-8')):
            if TABLA not in sentencia or not re.search(r'\b(INSERT\s+INTO|UPDATE)\s+(public\.)?' + TABLA, sentencia):
                continue
            for fila in _FILA.finditer(sentencia):
                tecnica = fila.group('tecnica')
                resultado[fila.group('regla')] = (tecnica, fila.group('nombre').replace("''", "'")) if tecnica else None
    return resultado


def tecnicas(carpeta=MIGRACIONES):
    """{técnica: {'name': nombre, 'rules': [reglas]}} de las reglas con técnica."""
    por_tecnica = {}
    for regla, valor in sorted(mapeo(carpeta).items()):
        if valor:
            tecnica, nombre = valor
            por_tecnica.setdefault(tecnica, {'name': nombre, 'rules': []})['rules'].append(regla)
    return dict(sorted(por_tecnica.items()))


def capa(carpeta=MIGRACIONES):
    """La capa de ATT&CK Navigator (formato de capa 4.5) con una técnica por fila y su número de reglas."""
    por_tecnica = tecnicas(carpeta)
    sin_tecnica = sorted(r for r, v in mapeo(carpeta).items() if v is None)
    maximo = max((len(t['rules']) for t in por_tecnica.values()), default=1)
    return {
        'name': 'LowTide: técnicas de reconocimiento que la plataforma detecta',
        'versions': {'attack': VERSION_ATTACK, 'navigator': '5.1.0', 'layer': '4.5'},
        'domain': 'enterprise-attack',
        'description': ('Técnicas de MITRE ATT&CK Enterprise v%s que las reglas de LowTide detectan en la superficie '
                        'expuesta de un dominio autorizado. El color es el número de reglas. LowTide mide exposición, '
                        'no compromiso: una técnica aquí es lo que un adversario podría aprovechar, no algo que haya '
                        'hecho. %d reglas no tienen técnica porque ninguna la nombra de forma directa. Sale de '
                        'db/migraciones (cirdan/navigator.py).') % (VERSION_ATTACK, len(sin_tecnica)),
        'sorting': 3,
        'layout': {'layout': 'side', 'showName': True, 'showID': True},
        'hideDisabled': False,
        'techniques': [
            {'techniqueID': tecnica, 'score': len(datos['rules']), 'enabled': True, 'showSubtechniques': True,
             'comment': 'Reglas de LowTide: %s' % ', '.join(datos['rules'])}
            for tecnica, datos in por_tecnica.items()
        ],
        'gradient': {'colors': ['#c7e9f1', '#1f7a99'], 'minValue': 0, 'maxValue': maximo},
        'legendItems': [{'label': 'Más reglas de LowTide la detectan', 'color': '#1f7a99'}],
        'metadata': [{'name': 'reglas_sin_tecnica', 'value': ', '.join(sin_tecnica)}],
        'showTacticRowBackground': False,
        'selectTechniquesAcrossTactics': True,
        'selectSubtechniquesWithParent': False,
    }


def texto(carpeta=MIGRACIONES):
    return json.dumps(capa(carpeta), ensure_ascii=False, indent=2) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description='Capa de ATT&CK Navigator de LowTide desde las migraciones.')
    parser.add_argument('--escribir', action='store_true', help='guarda la capa en %s' % CAPA.relative_to(RAIZ))
    args = parser.parse_args(argv)
    if args.escribir:
        CAPA.write_text(texto(), encoding='utf-8', newline='\n')
        print('capa guardada en %s' % CAPA.relative_to(RAIZ))
    else:
        sys.stdout.write(texto())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

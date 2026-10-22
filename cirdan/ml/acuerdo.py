"""Junta las etiquetas del lote del ML (#33, RC-65), arma dataset.csv y mide el acuerdo entre etiquetadores.

    python -m cirdan.ml.acuerdo                      # lee y escribe en datos/ml/rc65/
    python -m cirdan.ml.acuerdo --carpeta otra/carpeta

Lee maestro.jsonl y las etiquetas devueltas en etiquetas/etiquetador_N.csv, con las columnas id y etiqueta (nota es
opcional). Revisa que cada archivo traiga justo los ids de su copia, sin repetir, y que cada etiqueta sea alta, media
o baja. Si hay un error no escribe nada. Si falta el archivo de un etiquetador, sus filas del reparto salen del
dataset y lo demás sigue (plan B del reparto).

En el bloque común la etiqueta final es la mayoría de etiquetador_2 a etiquetador_4, y media si no hay mayoría.
etiquetador_1 conoce la clase esperada de cada plantilla, así que su etiqueta solo cuenta en el acuerdo.
Escribe dataset.csv y acuerdo.json: kappa de Fleiss con los 4 y sin etiquetador_1, acuerdo simple, kappa de Cohen
por pares y qué parte de las etiquetas coincide con clase_reglas y con la sensibilidad.
"""
import argparse
import csv
import json
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path

from cirdan.ml.generar_lote import CARPETA, ETIQUETADORES, SOLO_COMUN
from cirdan.ml.plantillas import CLASE_DE_SEVERIDAD, CLASES

CIEGOS = tuple(e for e in ETIQUETADORES if e != SOLO_COMUN)   # deciden la etiqueta final del bloque común
COLUMNAS_DATASET = ('id', 'plantilla', 'particion', 'tipo', 'antiguedad_dias', 'exposicion', 'sensibilidad',
                    'etiqueta', 'n_etiquetas', 'clase_reglas')
MINIMO_POR_CLASE = 60          # lo que pide #33
UMBRAL_TRIVIAL = 0.9           # si tantas etiquetas finales coinciden con clase_reglas, el lote es casi trivial


# ---------------------------------------------------------------- medidas

def fleiss_kappa(conteos):
    """Kappa de Fleiss. `conteos` trae, por fila, cuántos etiquetadores pusieron cada clase, y todas las filas suman lo
    mismo (2 o más). None si no hay filas o si todos usaron una sola clase."""
    if not conteos:
        return None
    n = sum(conteos[0])
    if n < 2 or any(sum(c) != n for c in conteos):
        raise ValueError('cada fila debe tener el mismo número de etiquetas, 2 o más')
    filas = len(conteos)
    observado = sum((sum(x * x for x in c) - n) / (n * (n - 1)) for c in conteos) / filas
    proporciones = [sum(c[j] for c in conteos) / (filas * n) for j in range(len(conteos[0]))]
    esperado = sum(p * p for p in proporciones)
    if esperado == 1:
        return None
    return (observado - esperado) / (1 - esperado)


def cohen_kappa(a, b):
    """Kappa de Cohen entre dos listas de etiquetas de las mismas filas. None si no se puede calcular."""
    if len(a) != len(b):
        raise ValueError('las dos listas deben tener las mismas filas')
    if not a:
        return None
    n = len(a)
    observado = sum(x == y for x, y in zip(a, b)) / n
    esperado = sum(a.count(c) * b.count(c) for c in set(a) | set(b)) / (n * n)
    if esperado == 1:
        return None
    return (observado - esperado) / (1 - esperado)


def etiqueta_final(valores):
    """La de la mayoría. media si no hay mayoría, por ejemplo cuando los tres difieren."""
    if not valores:
        return None
    clase, veces = Counter(valores).most_common(1)[0]
    return clase if veces > len(valores) / 2 else 'media'


def _r(x):
    return None if x is None else round(x, 4)


def _parte(pares):
    """Qué parte de los pares (etiqueta, referencia) coinciden."""
    return _r(sum(a == b for a, b in pares) / len(pares)) if pares else None


# ---------------------------------------------------------------- lectura y validación

def leer_maestro(carpeta):
    with open(Path(carpeta) / 'maestro.jsonl', encoding='utf-8') as f:
        return [json.loads(linea) for linea in f if linea.strip()]


def leer_etiquetas(carpeta, maestro):
    """({etiquetador: {id: etiqueta}}, etiquetadores sin archivo, errores)."""
    esperados = {e: {h['id'] for h in maestro if e in h['asignado_a']} for e in ETIQUETADORES}
    etiquetas, faltan, errores = {}, [], []
    for e in ETIQUETADORES:
        ruta = Path(carpeta) / 'etiquetas' / ('%s.csv' % e)
        if not ruta.exists():
            faltan.append(e)
            continue
        with open(ruta, encoding='utf-8-sig', newline='') as f:
            lector = csv.DictReader(f)
            if not {'id', 'etiqueta'} <= set(lector.fieldnames or ()):
                errores.append('%s: le faltan las columnas id y etiqueta' % ruta.name)
                continue
            suyas, vistos = {}, set()
            for linea, fila in enumerate(lector, 2):
                id_ = (fila['id'] or '').strip()
                valor = (fila['etiqueta'] or '').strip().lower()
                if id_ not in esperados[e]:
                    errores.append('%s, línea %d: el id %r no está en su copia' % (ruta.name, linea, id_))
                elif id_ in vistos:
                    errores.append('%s, línea %d: el id %s está repetido' % (ruta.name, linea, id_))
                elif valor not in CLASES:
                    errores.append('%s, línea %d: la etiqueta de %s es %r y debe ser alta, media o baja' % (
                        ruta.name, linea, id_, valor))
                else:
                    suyas[id_] = valor
                vistos.add(id_)
        sin_fila = sorted(esperados[e] - vistos)
        if sin_fila:
            errores.append('%s: faltan %d ids de su copia, por ejemplo %s' % (
                ruta.name, len(sin_fila), ', '.join(sin_fila[:3])))
        etiquetas[e] = suyas
    return etiquetas, faltan, errores


# ---------------------------------------------------------------- dataset y acuerdo

def armar_dataset(maestro, etiquetas):
    """Una fila por hallazgo con etiqueta. n_etiquetas cuenta las que decidieron la etiqueta final."""
    filas = []
    for h in maestro:
        quienes = CIEGOS if h['bloque'] == 'comun' else h['asignado_a']
        valores = [etiquetas[e][h['id']] for e in quienes if e in etiquetas]
        if not valores:
            continue
        c = h['caracteristicas']
        filas.append({'id': h['id'], 'plantilla': h['plantilla'], 'particion': h['particion'], 'tipo': c['tipo'],
                      'antiguedad_dias': c['antiguedad_dias'], 'exposicion': c['exposicion'],
                      'sensibilidad': c['sensibilidad'], 'etiqueta': etiqueta_final(valores),
                      'n_etiquetas': len(valores), 'clase_reglas': CLASE_DE_SEVERIDAD[h['severity']]})
    return filas


def _grupo(comun, etiquetas, quienes):
    quienes = [e for e in quienes if e in etiquetas]
    if len(quienes) < 2 or not comun:
        return {'etiquetadores': quienes, 'fleiss_kappa': None, 'acuerdo_simple': None}
    filas = [[etiquetas[e][h['id']] for e in quienes] for h in comun]
    return {'etiquetadores': quienes,
            'fleiss_kappa': _r(fleiss_kappa([[f.count(c) for c in CLASES] for f in filas])),
            'acuerdo_simple': _r(sum(len(set(f)) == 1 for f in filas) / len(filas))}


def _sin_mayoria(comun, etiquetas):
    """Filas del bloque común en que los ciegos no tienen mayoría, así que la etiqueta final queda en media."""
    n = 0
    for h in comun:
        valores = [etiquetas[e][h['id']] for e in CIEGOS if e in etiquetas]
        n += bool(valores) and Counter(valores).most_common(1)[0][1] * 2 <= len(valores)
    return n


def medir_acuerdo(maestro, etiquetas, faltan, dataset):
    comun = [h for h in maestro if h['bloque'] == 'comun']
    presentes = [e for e in ETIQUETADORES if e in etiquetas]
    pares = {}
    for a, b in combinations(presentes, 2):
        x, y = [etiquetas[a][h['id']] for h in comun], [etiquetas[b][h['id']] for h in comun]
        pares['%s con %s' % (a, b)] = {'cohen_kappa': _r(cohen_kappa(x, y)), 'acuerdo_simple': _parte(list(zip(x, y)))}
    coincidencia = {'final': {'clase_reglas': _parte([(f['etiqueta'], f['clase_reglas']) for f in dataset]),
                              'sensibilidad': _parte([(f['etiqueta'], f['sensibilidad']) for f in dataset])}}
    for e in presentes:
        suyas = [h for h in maestro if h['id'] in etiquetas[e]]
        coincidencia[e] = {
            'clase_reglas': _parte([(etiquetas[e][h['id']], CLASE_DE_SEVERIDAD[h['severity']]) for h in suyas]),
            'sensibilidad': _parte([(etiquetas[e][h['id']], h['caracteristicas']['sensibilidad']) for h in suyas])}
    por_clase = {c: sum(f['etiqueta'] == c for f in dataset) for c in CLASES}
    con_reglas = coincidencia['final']['clase_reglas']
    return {
        'filas_maestro': len(maestro),
        'filas_dataset': len(dataset),
        'faltan': faltan,
        'por_clase': por_clase,
        'por_particion': {p: sum(f['particion'] == p for f in dataset) for p in ('entrenamiento', 'prueba')},
        'al_menos_60_por_clase': all(n >= MINIMO_POR_CLASE for n in por_clase.values()),
        'bloque_comun': {
            'filas': len(comun),
            'los_4': _grupo(comun, etiquetas, ETIQUETADORES),
            'sin_etiquetador_1': _grupo(comun, etiquetas, CIEGOS),
            'sin_mayoria_queda_media': _sin_mayoria(comun, etiquetas),
            'cohen_por_pares': pares,
        },
        'coincidencia': coincidencia,
        'lote_trivial': con_reglas is not None and con_reglas >= UMBRAL_TRIVIAL,
    }


def escribir(carpeta, dataset, acuerdo):
    carpeta = Path(carpeta)
    with open(carpeta / 'dataset.csv', 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=COLUMNAS_DATASET)
        w.writeheader()
        w.writerows(dataset)
    with open(carpeta / 'acuerdo.json', 'w', encoding='utf-8', newline='') as f:
        f.write(json.dumps(acuerdo, ensure_ascii=False, indent=2) + '\n')


def procesar(carpeta):
    """(dataset, acuerdo, errores). Con errores no escribe nada."""
    maestro = leer_maestro(carpeta)
    etiquetas, faltan, errores = leer_etiquetas(carpeta, maestro)
    if errores:
        return None, None, errores
    dataset = armar_dataset(maestro, etiquetas)
    acuerdo = medir_acuerdo(maestro, etiquetas, faltan, dataset)
    escribir(carpeta, dataset, acuerdo)
    return dataset, acuerdo, []


def _main(argv=None):
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    p = argparse.ArgumentParser(description='Junta las etiquetas del lote del ML (#33) y mide el acuerdo')
    p.add_argument('--carpeta', default=str(CARPETA), help='carpeta del lote (por defecto datos/ml/rc65/)')
    a = p.parse_args(argv)
    dataset, acuerdo, errores = procesar(a.carpeta)
    if errores:
        print('No se escribió nada. Errores en las etiquetas:', *errores, sep='\n  ')
        return 1
    comun = acuerdo['bloque_comun']
    print('dataset.csv: %d filas (%s).' % (len(dataset), ', '.join('%s %d' % kv for kv in acuerdo['por_clase'].items())))
    print('Bloque común: kappa de Fleiss %s con los 4 y %s sin etiquetador_1.' % (
        comun['los_4']['fleiss_kappa'], comun['sin_etiquetador_1']['fleiss_kappa']))
    print('Coinciden con clase_reglas: %s. Con la sensibilidad: %s.' % (
        acuerdo['coincidencia']['final']['clase_reglas'], acuerdo['coincidencia']['final']['sensibilidad']))
    if acuerdo['faltan']:
        print('aviso: faltan las etiquetas de %s. Sus filas del reparto no están en el dataset.' % ', '.join(acuerdo['faltan']))
    if not acuerdo['al_menos_60_por_clase']:
        print('aviso: alguna clase tiene menos de %d filas.' % MINIMO_POR_CLASE)
    if acuerdo['lote_trivial']:
        print('aviso: el %.0f %% de las etiquetas finales coincide con clase_reglas. El lote es casi trivial.' % (
            100 * acuerdo['coincidencia']['final']['clase_reglas']))
    return 0


if __name__ == '__main__':
    sys.exit(_main())

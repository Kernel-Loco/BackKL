"""Junta las etiquetas del lote del ML (#33, RC-65), arma dataset.csv y mide el acuerdo entre etiquetadores.

    python -m cirdan.ml.acuerdo                      # lee y escribe en datos/ml/rc65/
    python -m cirdan.ml.acuerdo --carpeta otra/carpeta

Lee maestro.jsonl y las etiquetas devueltas en etiquetas/etiquetador_N.csv, con las columnas id y etiqueta (nota es
opcional). Revisa que cada archivo traiga justo los ids de su copia, sin repetir, y que cada etiqueta sea alta, media
o baja. Si hay un error, o si no hay etiquetas de personas ni del LLM, no escribe nada. Si falta el archivo de un etiquetador,
sus filas del reparto salen del dataset y lo demás sigue (plan B del reparto), salvo que las cubra el LLM.

En el bloque común la etiqueta final es la mayoría de etiquetador_2 a etiquetador_4, y media si no hay mayoría.
Si falta uno de los tres, deciden los otros dos: si no coinciden queda media, y n_etiquetas es 2.
etiquetador_1 conoce la clase esperada de cada plantilla, así que su etiqueta solo cuenta en el acuerdo. Ya no
entrega: sale en faltan, y entonces los_4 tiene los mismos etiquetadores que sin_etiquetador_1.
Escribe dataset.csv y acuerdo.json: kappa de Fleiss con los 4 y sin etiquetador_1, acuerdo simple, kappa de Cohen
por pares, qué parte de las etiquetas coincide con clase_reglas y con la sensibilidad, y el F1 macro que sacan en el
set de prueba las dos líneas base que #34 tiene que superar: las reglas y copiar la sensibilidad.

Etiquetador LLM, opcional y declarado: etiquetas/llm.csv trae todas las filas del maestro y etiquetas/llm_repeticion.csv
una segunda pasada del bloque común. Se revisan igual que los de las personas. El LLM nunca vota: no entra en la
etiqueta final, en el kappa de Fleiss ni en el kappa de Cohen entre personas. La sección llm de acuerdo.json trae su
kappa contra la etiqueta final de las personas en el bloque común y contra cada persona, si repite sus etiquetas y
cuánto coincide con clase_reglas y con la sensibilidad. El kappa contra la etiqueta final solo cuenta las filas en que
las personas tienen mayoría: la media por empate es una regla y no una etiqueta de personas. Si falta el archivo de
etiquetador_2, etiquetador_3 o etiquetador_4 y ese kappa es de UMBRAL_LLM o más, el LLM llena sus filas del reparto
con n_etiquetas 0. Si no, esas filas salen del dataset. Con alguno de ellos presente, nunca llena el bloque común.
Si ninguno de etiquetador_2 a etiquetador_4 entregó, todo el dataset sale del LLM, también el bloque común, con
n_etiquetas 0 y llm.solo_llm en true: el lote no depende de que las personas participen, pero ese dataset no tiene
validación de personas ni acuerdo entre personas. por_clase_solo_personas cuenta las clases sin las filas del LLM.

Otros LLM del bloque común, opcionales y declarados: etiquetas/llm_sonnet.csv y llm_haiku.csv (LLMS_COMUN) traen
justo las filas del bloque común, etiquetadas a ciegas por otros dos modelos. Se revisan como llm_repeticion.csv, y
sin llm.csv son un error. Tampoco votan ni cambian dataset.csv. Sin personas, como en la versión 1, cada fila
sigue con su etiqueta de llm.csv. Solo entran en llm.acuerdo_entre_llm, que mide en el bloque común el kappa de
Fleiss, el acuerdo simple y el kappa de Cohen por pares entre llm.csv y los que estén. Es None si hay menos de 2.
Así el lote mide un acuerdo sin personas: entre LLM, y declarado así.
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
UMBRAL_TRIVIAL = 0.9           # si tantas etiquetas finales coinciden con clase_reglas o con la sensibilidad, el
                               # modelo casi solo puede copiarlas
PARTICIONES = ('entrenamiento', 'prueba')
LLM = 'llm'                        # etiquetas/llm.csv: las etiquetas del LLM de todas las filas del maestro
LLM_REPETICION = 'llm_repeticion'  # etiquetas/llm_repeticion.csv: el bloque común otra vez, en otro orden
LLMS_COMUN = ('llm_sonnet', 'llm_haiku')   # etiquetas/llm_sonnet.csv y llm_haiku.csv: otros dos LLM, solo el bloque
                                           # común. Miden el acuerdo entre LLM y no votan
UMBRAL_LLM = 0.6                   # kappa mínimo del LLM contra la etiqueta final de las personas para cubrir faltantes


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


def macro_f1(reales, predichas):
    """F1 macro: el promedio del F1 de cada clase que sale en `reales` o en `predichas`. None si no hay filas."""
    if len(reales) != len(predichas):
        raise ValueError('las dos listas deben tener las mismas filas')
    if not reales:
        return None
    f1 = []
    for c in sorted(set(reales) | set(predichas)):
        aciertos = sum(r == p == c for r, p in zip(reales, predichas))
        f1.append(2 * aciertos / (reales.count(c) + predichas.count(c)))
    return sum(f1) / len(f1)


def mayoria(valores):
    """La clase que tiene más de la mitad de los valores. None si ninguna la tiene o si no hay valores."""
    if not valores:
        return None
    clase, veces = Counter(valores).most_common(1)[0]
    return clase if veces * 2 > len(valores) else None


def etiqueta_final(valores):
    """La de la mayoría. media si no hay mayoría, por ejemplo cuando los tres difieren."""
    if not valores:
        return None
    return mayoria(valores) or 'media'


def _r(x):
    return None if x is None else round(x, 4)


def _parte(pares):
    """Qué parte de los pares (etiqueta, referencia) coinciden."""
    return _r(sum(a == b for a, b in pares) / len(pares)) if pares else None


# ---------------------------------------------------------------- lectura y validación

def leer_maestro(carpeta):
    with open(Path(carpeta) / 'maestro.jsonl', encoding='utf-8') as f:
        return [json.loads(linea) for linea in f if linea.strip()]


def _leer_archivo(ruta, esperados, en, de):
    """({id: etiqueta}, errores) de un archivo de etiquetas que debe traer justo los ids de `esperados`. `en` y `de`
    dicen de dónde son esos ids en los errores, por ejemplo 'en su copia' y 'de su copia'."""
    suyas, vistos, errores = {}, set(), []
    with open(ruta, encoding='utf-8-sig', newline='') as f:
        lector = csv.DictReader(f)
        if not {'id', 'etiqueta'} <= set(lector.fieldnames or ()):
            return {}, ['%s: le faltan las columnas id y etiqueta' % ruta.name]
        for linea, fila in enumerate(lector, 2):
            id_ = (fila['id'] or '').strip()
            valor = (fila['etiqueta'] or '').strip().lower()
            if id_ not in esperados:
                errores.append('%s, línea %d: el id %r no está %s' % (ruta.name, linea, id_, en))
            elif id_ in vistos:
                errores.append('%s, línea %d: el id %s está repetido' % (ruta.name, linea, id_))
            elif valor not in CLASES:
                errores.append('%s, línea %d: la etiqueta de %s es %r y debe ser alta, media o baja' % (
                    ruta.name, linea, id_, valor))
            else:
                suyas[id_] = valor
            vistos.add(id_)
    sin_fila = sorted(esperados - vistos)
    if sin_fila:
        errores.append('%s: faltan %d ids %s, por ejemplo %s' % (ruta.name, len(sin_fila), de, ', '.join(sin_fila[:3])))
    return suyas, errores


def leer_etiquetas(carpeta, maestro):
    """({etiquetador: {id: etiqueta}}, etiquetadores sin archivo, errores)."""
    esperados = {e: {h['id'] for h in maestro if e in h['asignado_a']} for e in ETIQUETADORES}
    etiquetas, faltan, errores = {}, [], []
    for e in ETIQUETADORES:
        ruta = Path(carpeta) / 'etiquetas' / ('%s.csv' % e)
        if not ruta.exists():
            faltan.append(e)
            continue
        etiquetas[e], suyos = _leer_archivo(ruta, esperados[e], 'en su copia', 'de su copia')
        errores += suyos
    return etiquetas, faltan, errores


def leer_llm(carpeta, maestro):
    """(etiquetas del LLM o None, su repetición del bloque común o None, errores). Los dos archivos son opcionales.
    llm.csv debe traer todas las filas del maestro y llm_repeticion.csv justo las del bloque común."""
    archivos = ((LLM, {h['id'] for h in maestro}, 'en el maestro', 'del maestro'),
                (LLM_REPETICION, {h['id'] for h in maestro if h['bloque'] == 'comun'}, 'en el bloque común',
                 'del bloque común'))
    leidas, errores = {}, []
    for nombre, esperados, en, de in archivos:
        ruta = Path(carpeta) / 'etiquetas' / ('%s.csv' % nombre)
        if ruta.exists():
            leidas[nombre], suyos = _leer_archivo(ruta, esperados, en, de)
            errores += suyos
    if LLM_REPETICION in leidas and LLM not in leidas:
        errores.append('%s.csv: está la repetición del LLM pero falta %s.csv' % (LLM_REPETICION, LLM))
    return leidas.get(LLM), leidas.get(LLM_REPETICION), errores


def leer_llms_comun(carpeta, maestro, hay_llm):
    """({nombre: {id: etiqueta}} de los LLM de LLMS_COMUN que tienen archivo, errores). Son opcionales, deben traer
    justo las filas del bloque común y son un error si no hay llm.csv (`hay_llm`)."""
    esperados = {h['id'] for h in maestro if h['bloque'] == 'comun'}
    leidas, errores = {}, []
    for nombre in LLMS_COMUN:
        ruta = Path(carpeta) / 'etiquetas' / ('%s.csv' % nombre)
        if not ruta.exists():
            continue
        leidas[nombre], suyos = _leer_archivo(ruta, esperados, 'en el bloque común', 'del bloque común')
        errores += suyos
        if not hay_llm:
            errores.append('%s.csv: están las etiquetas de %s pero falta %s.csv' % (nombre, nombre, LLM))
    return leidas, errores


# ---------------------------------------------------------------- dataset y acuerdo

def armar_dataset(maestro, etiquetas, llm=None, cubrir=(), solo_llm=False):
    """Una fila por hallazgo con etiqueta. n_etiquetas cuenta las etiquetas de personas que decidieron la final.
    Las filas del reparto de los etiquetadores en `cubrir` llevan la etiqueta del LLM y n_etiquetas 0. Las del bloque
    común solo con `solo_llm`, cuando ninguno de los ciegos entregó y todo sale del LLM."""
    filas = []
    for h in maestro:
        quienes = CIEGOS if h['bloque'] == 'comun' else h['asignado_a']
        valores = [etiquetas[e][h['id']] for e in quienes if e in etiquetas]
        if valores:
            etiqueta = etiqueta_final(valores)
        elif llm and (solo_llm or h['bloque'] == 'reparto' and set(h['asignado_a']) & set(cubrir)):
            etiqueta = llm[h['id']]
        else:
            continue
        c = h['caracteristicas']
        filas.append({'id': h['id'], 'plantilla': h['plantilla'], 'particion': h['particion'], 'tipo': c['tipo'],
                      'antiguedad_dias': c['antiguedad_dias'], 'exposicion': c['exposicion'],
                      'sensibilidad': c['sensibilidad'], 'etiqueta': etiqueta,
                      'n_etiquetas': len(valores), 'clase_reglas': CLASE_DE_SEVERIDAD[h['severity']]})
    return filas


def finales_comun(maestro, etiquetas):
    """({id: etiqueta final de las personas}, filas sin mayoría) en el bloque común. Solo trae las filas en que los
    ciegos que entregaron tienen mayoría. En las otras la final queda media por regla, no porque las personas la
    pusieran. Con 2 ciegos son las filas en que coinciden. Con 1, todas."""
    finales, sin_mayoria = {}, 0
    for h in maestro:
        if h['bloque'] != 'comun':
            continue
        valores = [etiquetas[e][h['id']] for e in CIEGOS if e in etiquetas]
        clase = mayoria(valores)
        if clase:
            finales[h['id']] = clase
        elif valores:
            sin_mayoria += 1
    return finales, sin_mayoria


def medir_entre_llm(maestro, llm, otros):
    """llm.acuerdo_entre_llm: kappa de Fleiss, acuerdo simple y kappa de Cohen por pares en el bloque común entre
    llm.csv y los LLM de LLMS_COMUN que estén en `otros`. None si son menos de 2."""
    todos = dict(otros or {})
    if llm is not None:
        todos[LLM] = llm
    quienes = [n for n in (LLM,) + LLMS_COMUN if n in todos]
    if len(quienes) < 2:
        return None
    comun = [h for h in maestro if h['bloque'] == 'comun']
    grupo = _grupo(comun, todos, quienes)
    return {'etiquetadores': quienes, 'filas': len(comun), 'fleiss_kappa': grupo['fleiss_kappa'],
            'acuerdo_simple': grupo['acuerdo_simple'], 'cohen_por_pares': _pares(comun, todos, quienes)}


def medir_llm(maestro, etiquetas, faltan, llm, repeticion, otros=None):
    """(sección llm de acuerdo.json, etiquetadores cuyas filas del reparto llena el LLM). El LLM no vota: aquí solo
    se compara con las personas, y cubre a quien no entregó si su kappa contra la etiqueta final es de UMBRAL_LLM o
    más. Si ninguno de los ciegos entregó, no hay contra qué medirlo y cubre todo (solo_llm). `otros` son las
    etiquetas de LLMS_COMUN: solo cuentan en acuerdo_entre_llm."""
    if llm is None:
        return {'esta': False, 'umbral_kappa': UMBRAL_LLM, 'contra_final_personas': None, 'contra_cada_persona': {},
                'repeticion': None, 'acuerdo_entre_llm': None, 'coincidencia': None, 'alcanza_umbral': False,
                'cubre_faltantes': False, 'solo_llm': False, 'motivo': 'No hay etiquetas del LLM.',
                'filas_cubiertas': {}}, []
    sin_archivo = [e for e in faltan if e in CIEGOS]   # etiquetador_1 no tiene filas del reparto
    comun = [h['id'] for h in maestro if h['bloque'] == 'comun']

    def contra(referencia):
        ids = [i for i in comun if i in referencia]
        x, y = [llm[i] for i in ids], [referencia[i] for i in ids]
        return {'filas': len(ids), 'cohen_kappa': _r(cohen_kappa(x, y)), 'acuerdo_simple': _parte(list(zip(x, y)))}

    finales, sin_mayoria = finales_comun(maestro, etiquetas)
    personas = [e for e in CIEGOS if e in etiquetas]
    contra_final = dict(contra(finales), filas_sin_mayoria_excluidas=sin_mayoria, personas=personas)
    kappa = contra_final['cohen_kappa']
    alcanza = kappa is not None and kappa >= UMBRAL_LLM   # con el kappa redondeado, el mismo que sale en acuerdo.json
    texto = 'kappa del LLM contra la etiqueta final de las personas en el bloque común'
    if kappa is None:
        motivo = 'No se pudo calcular el %s.' % texto
    elif alcanza:
        motivo = 'El %s es %s, de %s o más.' % (texto, kappa, UMBRAL_LLM)
    else:
        motivo = 'El %s es %s, menor que %s.' % (texto, kappa, UMBRAL_LLM)
    solo_llm = not personas   # ninguno de los ciegos entregó: no hay contra qué medir al LLM
    if solo_llm:
        motivo = ('Ninguno de %s entregó etiquetas. Todo el dataset sale del LLM, también el bloque común, con '
                  'n_etiquetas 0 y sin validación de personas.' % ', '.join(CIEGOS))
    else:
        if len(personas) == 1:
            motivo += ' La referencia es una sola persona, %s.' % personas[0]
        if not sin_archivo:
            motivo += ' No falta nadie del reparto.'
        elif alcanza:
            motivo += ' Cubre las filas del reparto de %s.' % ', '.join(sin_archivo)
        else:
            motivo += ' Las filas del reparto de %s salen del dataset.' % ', '.join(sin_archivo)
    cubrir = sin_archivo if alcanza or solo_llm else []
    filas_cubiertas = {e: sum(h['bloque'] == 'reparto' and h['asignado_a'] == [e] for h in maestro) for e in cubrir}
    if solo_llm:
        filas_cubiertas['bloque_comun'] = len(comun)
    seccion = {
        'esta': True,
        'umbral_kappa': UMBRAL_LLM,
        'contra_final_personas': contra_final,
        'contra_cada_persona': {e: contra(etiquetas[e]) for e in ETIQUETADORES if e in etiquetas},
        'repeticion': None if repeticion is None else contra(repeticion),
        'acuerdo_entre_llm': medir_entre_llm(maestro, llm, otros),
        'coincidencia': {
            'clase_reglas': _parte([(llm[h['id']], CLASE_DE_SEVERIDAD[h['severity']]) for h in maestro]),
            'sensibilidad': _parte([(llm[h['id']], h['caracteristicas']['sensibilidad']) for h in maestro])},
        'alcanza_umbral': alcanza,
        'cubre_faltantes': bool(cubrir),
        'solo_llm': solo_llm,
        'motivo': motivo,
        'filas_cubiertas': filas_cubiertas,
    }
    return seccion, cubrir


def _grupo(comun, etiquetas, quienes):
    quienes = [e for e in quienes if e in etiquetas]
    if len(quienes) < 2 or not comun:
        return {'etiquetadores': quienes, 'fleiss_kappa': None, 'acuerdo_simple': None}
    filas = [[etiquetas[e][h['id']] for e in quienes] for h in comun]
    return {'etiquetadores': quienes,
            'fleiss_kappa': _r(fleiss_kappa([[f.count(c) for c in CLASES] for f in filas])),
            'acuerdo_simple': _r(sum(len(set(f)) == 1 for f in filas) / len(filas))}


def _pares(comun, etiquetas, quienes):
    """Kappa de Cohen y acuerdo simple de cada par de `quienes` en las filas de `comun`."""
    pares = {}
    for a, b in combinations(quienes, 2):
        x, y = [etiquetas[a][h['id']] for h in comun], [etiquetas[b][h['id']] for h in comun]
        pares['%s con %s' % (a, b)] = {'cohen_kappa': _r(cohen_kappa(x, y)), 'acuerdo_simple': _parte(list(zip(x, y)))}
    return pares


def medir_acuerdo(maestro, etiquetas, faltan, dataset, llm=None):
    """acuerdo.json. `llm` es la sección que da medir_llm(). Sin ella dice que no hay LLM."""
    if llm is None:
        llm, _ = medir_llm(maestro, etiquetas, faltan, None, None)
    comun = [h for h in maestro if h['bloque'] == 'comun']
    presentes = [e for e in ETIQUETADORES if e in etiquetas]
    pares = _pares(comun, etiquetas, presentes)

    def con_referencias(filas):
        return {'clase_reglas': _parte([(f['etiqueta'], f['clase_reglas']) for f in filas]),
                'sensibilidad': _parte([(f['etiqueta'], f['sensibilidad']) for f in filas])}

    coincidencia = {'final': con_referencias(dataset)}
    for p in PARTICIONES:
        coincidencia['final_%s' % p] = con_referencias([f for f in dataset if f['particion'] == p])
    for e in presentes:
        suyas = [h for h in maestro if h['id'] in etiquetas[e]]
        coincidencia[e] = {
            'clase_reglas': _parte([(etiquetas[e][h['id']], CLASE_DE_SEVERIDAD[h['severity']]) for h in suyas]),
            'sensibilidad': _parte([(etiquetas[e][h['id']], h['caracteristicas']['sensibilidad']) for h in suyas])}
    prueba = [f for f in dataset if f['particion'] == 'prueba']
    reales = [f['etiqueta'] for f in prueba]
    por_clase = {c: sum(f['etiqueta'] == c for f in dataset) for c in CLASES}
    con_reglas = coincidencia['final']['clase_reglas']
    con_rubrica = coincidencia['final']['sensibilidad']
    return {
        'filas_maestro': len(maestro),
        'filas_dataset': len(dataset),
        'faltan': faltan,
        'por_clase': por_clase,
        # sin las filas que llenó el LLM (n_etiquetas 0)
        'por_clase_solo_personas': {c: sum(f['etiqueta'] == c and f['n_etiquetas'] > 0 for f in dataset)
                                    for c in CLASES},
        'por_particion': {p: sum(f['particion'] == p for f in dataset) for p in PARTICIONES},
        'al_menos_60_por_clase': all(n >= MINIMO_POR_CLASE for n in por_clase.values()),
        # F1 macro en el set de prueba de lo que #34 tiene que superar: predecir clase_reglas o copiar la sensibilidad
        'linea_base_prueba': {
            'filas': len(prueba),
            'f1_macro_clase_reglas': _r(macro_f1(reales, [f['clase_reglas'] for f in prueba])),
            'f1_macro_sensibilidad': _r(macro_f1(reales, [f['sensibilidad'] for f in prueba])),
        },
        'bloque_comun': {
            'filas': len(comun),
            'los_4': _grupo(comun, etiquetas, ETIQUETADORES),
            'sin_etiquetador_1': _grupo(comun, etiquetas, CIEGOS),
            'sin_mayoria_queda_media': finales_comun(maestro, etiquetas)[1],   # la final queda en media
            'cohen_por_pares': pares,
        },
        'coincidencia': coincidencia,
        'lote_trivial': con_reglas is not None and con_reglas >= UMBRAL_TRIVIAL,
        'rubrica_trivial': con_rubrica is not None and con_rubrica >= UMBRAL_TRIVIAL,
        'llm': llm,
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
    llm, repeticion, errores_llm = leer_llm(carpeta, maestro)
    otros, errores_otros = leer_llms_comun(carpeta, maestro, llm is not None)
    errores += errores_llm + errores_otros
    if not etiquetas and llm is None and not errores:
        errores = ['no hay etiquetas de personas ni del LLM en %s' % (Path(carpeta) / 'etiquetas')]
    if errores:
        return None, None, errores
    seccion_llm, cubrir = medir_llm(maestro, etiquetas, faltan, llm, repeticion, otros)
    dataset = armar_dataset(maestro, etiquetas, llm, cubrir, seccion_llm['solo_llm'])
    acuerdo = medir_acuerdo(maestro, etiquetas, faltan, dataset, seccion_llm)
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
        print('No se escribió nada. Errores:', *errores, sep='\n  ')
        return 1
    comun = acuerdo['bloque_comun']
    print('dataset.csv: %d filas (%s).' % (len(dataset), ', '.join('%s %d' % kv for kv in acuerdo['por_clase'].items())))
    if not comun['sin_etiquetador_1']['etiquetadores']:
        print('Bloque común: ninguno de %s entregó, así que no hay kappa de Fleiss.' % ', '.join(CIEGOS))
    elif SOLO_COMUN in acuerdo['faltan']:   # los_4 tiene los mismos etiquetadores que sin_etiquetador_1
        print('Bloque común: kappa de Fleiss %s entre %s. %s no entregó, así que no hay kappa con los 4.' % (
            comun['sin_etiquetador_1']['fleiss_kappa'], ', '.join(comun['sin_etiquetador_1']['etiquetadores']),
            SOLO_COMUN))
    else:
        print('Bloque común: kappa de Fleiss %s con los 4 y %s sin etiquetador_1.' % (
            comun['los_4']['fleiss_kappa'], comun['sin_etiquetador_1']['fleiss_kappa']))
    print('Coinciden con clase_reglas: %s. Con la sensibilidad: %s.' % (
        acuerdo['coincidencia']['final']['clase_reglas'], acuerdo['coincidencia']['final']['sensibilidad']))
    base = acuerdo['linea_base_prueba']
    print('F1 macro en prueba que #34 tiene que superar: %s con clase_reglas y %s copiando la sensibilidad.' % (
        base['f1_macro_clase_reglas'], base['f1_macro_sensibilidad']))
    llm = acuerdo['llm']
    if llm['esta']:
        cubiertas = llm['filas_cubiertas']
        print('Etiquetador LLM (no vota): kappa de Cohen %s contra la etiqueta final de las personas en el bloque '
              'común. Filas que cubre: %s.' % (llm['contra_final_personas']['cohen_kappa'],
                                               ', '.join('%s %d' % kv for kv in cubiertas.items()) or 'ninguna'))
        entre = llm['acuerdo_entre_llm']
        if entre:
            print('Acuerdo entre LLM en el bloque común (no votan): kappa de Fleiss %s entre %s, en %d filas.' % (
                entre['fleiss_kappa'], ', '.join(entre['etiquetadores']), entre['filas']))
        if cubiertas and len(llm['contra_final_personas']['personas']) == 1:
            print('aviso: el LLM cubre con un kappa medido contra una sola persona.')
        if llm['solo_llm']:
            print('aviso: ninguna persona entregó etiquetas. Todo el dataset sale del LLM, sin validación de personas '
                  'ni acuerdo entre personas.')
    else:
        print('Etiquetador LLM: no hay etiquetas del LLM.')
    if acuerdo['faltan']:
        cubiertos = [e for e in llm['filas_cubiertas'] if e in CIEGOS]
        fuera = [e for e in acuerdo['faltan'] if e in CIEGOS and e not in cubiertos]
        texto = 'aviso: faltan las etiquetas de %s.' % ', '.join(acuerdo['faltan'])
        if cubiertos:
            texto += ' El LLM cubre las filas del reparto de %s.' % ', '.join(cubiertos)
        if fuera:
            texto += ' Las filas del reparto de %s no están en el dataset.' % ', '.join(fuera)
        print(texto)
    if not acuerdo['al_menos_60_por_clase']:
        print('aviso: alguna clase tiene menos de %d filas.' % MINIMO_POR_CLASE)
    if acuerdo['lote_trivial']:
        print('aviso: el %.0f %% de las etiquetas finales coincide con clase_reglas. El lote es casi trivial.' % (
            100 * acuerdo['coincidencia']['final']['clase_reglas']))
    if acuerdo['rubrica_trivial']:
        print('aviso: el %.0f %% de las etiquetas finales coincide con la sensibilidad. El modelo casi solo puede '
              'copiar la rúbrica.' % (100 * acuerdo['coincidencia']['final']['sensibilidad']))
    return 0


if __name__ == '__main__':
    sys.exit(_main())

"""Muestra ciega y comparación futura de etiquetas humanas con las etiquetas LLM de RC-65."""
import argparse
import csv
import json
import random
from collections import Counter
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

from cirdan.ml import acuerdo, generar_lote
from cirdan.ml.modelo import DATASET, RAIZ
from cirdan.ml.plantillas import CLASES

CARPETA = RAIZ / 'datos' / 'ml' / 'rc65'
MAESTRO = CARPETA / 'maestro.jsonl'
MUESTRA = CARPETA / 'auditoria_humana_ciega.csv'
NUM_CASOS_POR_CLASE = 15
SEMILLA = 67
COLUMNAS = generar_lote.COLUMNAS_COPIA


def crear_muestra(dataset_path=DATASET, maestro_path=MAESTRO, salida=MUESTRA):
    dataset = pd.read_csv(dataset_path)
    if not {'id', 'particion', 'etiqueta'} <= set(dataset.columns):
        raise ValueError('el dataset necesita id, particion y etiqueta')
    prueba = dataset[dataset['particion'] == 'prueba']
    if prueba.empty:
        raise ValueError('la muestra debe salir de la partición de prueba')
    rng = random.Random(SEMILLA)
    seleccionados = []
    for clase in CLASES:
        ids = prueba.loc[prueba['etiqueta'] == clase, 'id'].tolist()
        if len(ids) < NUM_CASOS_POR_CLASE:
            raise ValueError('no hay 15 filas de prueba para la clase %s' % clase)
        seleccionados.extend(rng.sample(ids, NUM_CASOS_POR_CLASE))
    rng.shuffle(seleccionados)

    with Path(maestro_path).open(encoding='utf-8') as archivo:
        filas_maestro = [json.loads(linea) for linea in archivo if linea.strip()]
    maestro = {}
    for fila in filas_maestro:
        id_fila = fila.get('id')
        if not id_fila or id_fila in maestro:
            raise ValueError('el maestro contiene ids duplicados o líneas sin id')
        maestro[id_fila] = fila
    faltantes = set(seleccionados) - set(maestro)
    if faltantes:
        raise ValueError('faltan ids del dataset en el maestro: %s' % ', '.join(sorted(faltantes)))

    salida = Path(salida)
    salida.parent.mkdir(parents=True, exist_ok=True)
    with salida.open('w', encoding='utf-8', newline='') as archivo:
        escritor = csv.DictWriter(archivo, fieldnames=COLUMNAS, lineterminator='\n')
        escritor.writeheader()
        for id_fila in seleccionados:
            escritor.writerow(generar_lote.fila_copia(maestro[id_fila]))
    return {'archivo': str(salida), 'filas': len(seleccionados),
            'por_clase_llm': {clase: NUM_CASOS_POR_CLASE for clase in CLASES}}


def comparar(etiquetas_path, dataset_path=DATASET, informe=None):
    dataset = pd.read_csv(dataset_path)
    prueba = dataset[dataset['particion'] == 'prueba']
    referencia = dict(zip(prueba['id'], prueba['etiqueta']))
    with Path(etiquetas_path).open(encoding='utf-8-sig', newline='') as archivo:
        lector = csv.DictReader(archivo)
        if not lector.fieldnames or not {'id', 'etiqueta'} <= set(lector.fieldnames):
            raise ValueError('el CSV anotado necesita columnas id y etiqueta')
        filas = list(lector)
    ids = [fila['id'] for fila in filas]
    if len(filas) != NUM_CASOS_POR_CLASE * len(CLASES) or len(ids) != len(set(ids)):
        raise ValueError('el CSV debe contener 45 ids únicos de la muestra ciega')
    if set(ids) - set(referencia):
        raise ValueError('el CSV contiene ids que no pertenecen a la partición de prueba')
    anotaciones = [(fila.get('etiqueta') or '').strip().lower() for fila in filas]
    if any(etiqueta not in CLASES for etiqueta in anotaciones):
        raise ValueError('cada fila debe tener etiqueta alta, media o baja')
    esperadas = [referencia[id_fila] for id_fila in ids]
    if Counter(esperadas) != Counter({clase: NUM_CASOS_POR_CLASE for clase in CLASES}):
        raise ValueError('la muestra debe contener 15 casos por clase LLM')

    resultado = {
        'filas': len(filas),
        'origen_referencia': 'etiquetas LLM de la partición de prueba; no son verdad-terreno',
        'muestra': '15 por clase LLM, seleccionada a ciegas',
        'acuerdo': {
            'exactitud': float(accuracy_score(esperadas, anotaciones)),
            'cohen_kappa': acuerdo.cohen_kappa(esperadas, anotaciones),
            'macro_f1_humano_vs_llm': float(f1_score(
                esperadas, anotaciones, labels=CLASES, average='macro', zero_division=0)),
            'matriz_confusion': confusion_matrix(esperadas, anotaciones, labels=CLASES).tolist(),
            'orden_matriz': list(CLASES),
        },
    }
    if informe is not None:
        informe = Path(informe)
        informe.parent.mkdir(parents=True, exist_ok=True)
        informe.write_text(json.dumps(resultado, ensure_ascii=False, indent=2) + '\n',
                           encoding='utf-8', newline='\n')
    return resultado


def main():
    parser = argparse.ArgumentParser(description='Muestra ciega y acuerdo humano-LLM para RC-65')
    subparsers = parser.add_subparsers(dest='accion', required=True)
    crear = subparsers.add_parser('crear', help='genera 45 casos ciegos, 15 por clase LLM')
    crear.add_argument('--salida', type=Path, default=MUESTRA)
    medir = subparsers.add_parser('comparar', help='compara el CSV anotado con las etiquetas LLM')
    medir.add_argument('etiquetas', type=Path)
    medir.add_argument('--informe', type=Path)
    argumentos = parser.parse_args()
    if argumentos.accion == 'crear':
        resultado = crear_muestra(salida=argumentos.salida)
    else:
        resultado = comparar(argumentos.etiquetas, informe=argumentos.informe)
    print(json.dumps(resultado, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

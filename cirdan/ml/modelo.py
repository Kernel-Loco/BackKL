"""Entrenamiento y evaluación del clasificador v1 (#34)."""
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder

RAIZ = Path(__file__).resolve().parents[2]
DATASET = RAIZ / 'datos' / 'ml' / 'rc65' / 'dataset.csv'
ARTEFACTO = Path(__file__).with_name('modelo_v1.joblib')
FICHA = RAIZ / 'docs' / 'modelo_ml_v1.json'
VERSION = 'v1-rc65-1'
CARACTERISTICAS_CATEGORICAS = ('tipo', 'exposicion', 'sensibilidad')
CARACTERISTICAS_NUMERICAS = ('antiguedad_dias',)
CARACTERISTICAS = (*CARACTERISTICAS_CATEGORICAS, *CARACTERISTICAS_NUMERICAS)
CLASES = ('alta', 'baja', 'media')


def crear_pipeline():
    preprocesador = ColumnTransformer(
        [
            ('categoricas', OneHotEncoder(handle_unknown='ignore'), list(CARACTERISTICAS_CATEGORICAS)),
            ('numericas', 'passthrough', list(CARACTERISTICAS_NUMERICAS)),
        ],
        verbose_feature_names_out=False,
    )
    clasificador = ExtraTreesClassifier(
        n_estimators=300,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=34,
        n_jobs=1,
    )
    return make_pipeline(preprocesador, clasificador)


def _metricas(reales, predichas, clases):
    precision, recall, f1, soporte = precision_recall_fscore_support(
        reales, predichas, labels=clases, zero_division=0)
    return {
        'por_clase': {
            clase: {'precision': float(p), 'recall': float(r), 'f1': float(f), 'soporte': int(n)}
            for clase, p, r, f, n in zip(clases, precision, recall, f1, soporte)
        },
        'macro_f1': float(f1_score(reales, predichas, labels=clases, average='macro', zero_division=0)),
        'matriz_confusion': confusion_matrix(reales, predichas, labels=clases).tolist(),
        'orden_matriz': list(clases),
    }


def entrenar(dataset_path=DATASET):
    """Entrena solo con la partición de entrenamiento y mide las dos líneas base en prueba."""
    dataset = pd.read_csv(dataset_path)
    requeridas = (*CARACTERISTICAS, 'etiqueta', 'clase_reglas', 'particion', 'plantilla')
    if any(columna not in dataset.columns for columna in requeridas):
        raise ValueError('faltan columnas de características, etiquetas o partición en el dataset')
    if dataset['plantilla'].isna().any():
        raise ValueError('cada fila debe tener una plantilla para separar entrenamiento y prueba')
    particiones = {'entrenamiento', 'prueba'}
    if dataset['particion'].isna().any() or not set(dataset['particion']) <= particiones:
        raise ValueError('partición inválida; solo se permite entrenamiento o prueba')
    if (dataset.groupby('plantilla')['particion'].nunique() > 1).any():
        raise ValueError('una plantilla no puede aparecer en entrenamiento y prueba')
    if dataset['etiqueta'].isna().any() or set(dataset['etiqueta']) != set(CLASES):
        raise ValueError('etiqueta debe cubrir alta, baja y media')
    for columna in ('clase_reglas', 'sensibilidad'):
        if dataset[columna].isna().any() or not set(dataset[columna]) <= set(CLASES):
            raise ValueError('%s contiene una etiqueta inválida' % columna)

    entrenamiento = dataset[dataset['particion'] == 'entrenamiento']
    prueba = dataset[dataset['particion'] == 'prueba']
    if entrenamiento.empty or prueba.empty:
        raise ValueError('el dataset necesita filas de entrenamiento y prueba')
    if set(entrenamiento['etiqueta']) != set(CLASES) or set(prueba['etiqueta']) != set(CLASES):
        raise ValueError('cada partición debe contener alta, baja y media')

    pipeline = crear_pipeline()
    pipeline.fit(entrenamiento[list(CARACTERISTICAS)], entrenamiento['etiqueta'])
    predichas = pipeline.predict(prueba[list(CARACTERISTICAS)])
    clases = _clases_presentes(dataset)
    metricas_modelo = _metricas(prueba['etiqueta'], predichas, clases)
    f1_reglas = float(f1_score(prueba['etiqueta'], prueba['clase_reglas'], labels=clases,
                               average='macro', zero_division=0))
    f1_sensibilidad = float(f1_score(prueba['etiqueta'], prueba['sensibilidad'], labels=clases,
                                     average='macro', zero_division=0))
    supera_reglas = metricas_modelo['macro_f1'] > f1_reglas
    metricas = {
        'version': VERSION,
        'algoritmo': 'ExtraTreesClassifier',
        'dataset': 'datos/ml/rc65/dataset.csv',
        'origen_etiquetas': 'LLM; sin validación humana',
        'caracteristicas': list(CARACTERISTICAS),
        'particionamiento': 'por_plantilla',
        'filas_entrenamiento': int(len(entrenamiento)),
        'filas_prueba': int(len(prueba)),
        'lineas_base': {'reglas_macro_f1': f1_reglas, 'sensibilidad_macro_f1': f1_sensibilidad},
        'modelo': metricas_modelo,
        'supera_reglas': supera_reglas,
        'supera_sensibilidad': metricas_modelo['macro_f1'] > f1_sensibilidad,
        'integrable': supera_reglas,
    }
    return {'version': VERSION, 'pipeline': pipeline, 'metrics': metricas}


def _clases_presentes(dataset):
    return sorted(set(dataset['etiqueta']))


def guardar(bundle, artefacto=ARTEFACTO, ficha=FICHA):
    artefacto.parent.mkdir(parents=True, exist_ok=True)
    ficha.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, artefacto, compress=3)
    ficha.write_text(json.dumps(bundle['metrics'], ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    bundle = entrenar()
    guardar(bundle)
    print(json.dumps(bundle['metrics'], ensure_ascii=False, indent=2))
    print('Modelo guardado en %s' % ARTEFACTO.relative_to(RAIZ))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
"""Entrenamiento, evaluación y calibración del clasificador ML v1 (#34, #67)."""
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, confusion_matrix, f1_score, precision_recall_fscore_support
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder

from cirdan.ml.plantillas import REGLAS

RAIZ = Path(__file__).resolve().parents[2]
DATASET = RAIZ / 'datos' / 'ml' / 'rc65' / 'dataset.csv'
ARTEFACTO = Path(__file__).with_name('modelo_v1.joblib')
FICHA = RAIZ / 'docs' / 'modelo_ml_v1.json'
VERSION = 'v1-rc67-1'
CARACTERISTICAS_CATEGORICAS = ('tipo', 'exposicion', 'sensibilidad')
CARACTERISTICAS_NUMERICAS = ('antiguedad_dias',)
CARACTERISTICAS = (*CARACTERISTICAS_CATEGORICAS, *CARACTERISTICAS_NUMERICAS)
CLASES = ('alta', 'baja', 'media')
CODIGOS_ENTRENADOS = frozenset(REGLAS)
SEMILLA_EVALUACION = 67
NUM_SPLITS = 3
NUM_BOOTSTRAPS = 2000


def crear_pipeline(caracteristicas=CARACTERISTICAS):
    caracteristicas = tuple(caracteristicas)
    if not caracteristicas or not set(caracteristicas) <= set(CARACTERISTICAS):
        raise ValueError('caracteristicas debe ser un subconjunto no vacío de las características del modelo')
    categoricas = [columna for columna in caracteristicas if columna in CARACTERISTICAS_CATEGORICAS]
    numericas = [columna for columna in caracteristicas if columna in CARACTERISTICAS_NUMERICAS]
    transformadores = []
    if categoricas:
        transformadores.append(('categoricas', OneHotEncoder(handle_unknown='ignore'), categoricas))
    if numericas:
        transformadores.append(('numericas', 'passthrough', numericas))
    preprocesador = ColumnTransformer(transformadores, verbose_feature_names_out=False)
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


def _probabilidades_alineadas(pipeline, datos):
    probabilidades = np.zeros((len(datos), len(CLASES)), dtype=float)
    predichas = pipeline.predict_proba(datos)
    for indice, clase in enumerate(pipeline.classes_):
        probabilidades[:, CLASES.index(clase)] = predichas[:, indice]
    return probabilidades


def _probabilidades_oof(entrenamiento, caracteristicas=CARACTERISTICAS):
    caracteristicas = entrenamiento[list(caracteristicas)]
    etiquetas = entrenamiento['etiqueta'].to_numpy()
    grupos = entrenamiento['plantilla'].to_numpy()
    probabilidades = np.zeros((len(entrenamiento), len(CLASES)), dtype=float)
    asignadas = np.zeros(len(entrenamiento), dtype=bool)
    metricas_folds = []
    splitter = StratifiedGroupKFold(
        n_splits=NUM_SPLITS, shuffle=True, random_state=SEMILLA_EVALUACION)
    for numero, (indices_train, indices_validacion) in enumerate(
            splitter.split(caracteristicas, etiquetas, groups=grupos), 1):
        plantillas_train = set(grupos[indices_train])
        plantillas_validacion = set(grupos[indices_validacion])
        if plantillas_train & plantillas_validacion:
            raise ValueError('una plantilla aparece en entrenamiento y validación cruzada')
        pipeline = crear_pipeline(caracteristicas.columns)
        pipeline.fit(caracteristicas.iloc[indices_train], etiquetas[indices_train])
        probabilidades[indices_validacion] = _probabilidades_alineadas(
            pipeline, caracteristicas.iloc[indices_validacion])
        asignadas[indices_validacion] = True
        predichas = np.asarray(CLASES)[probabilidades[indices_validacion].argmax(axis=1)]
        metricas_folds.append({
            'fold': numero,
            'macro_f1': float(f1_score(
                etiquetas[indices_validacion], predichas, labels=CLASES, average='macro', zero_division=0)),
            'plantillas_validacion': sorted(plantillas_validacion),
        })
    if not asignadas.all():
        raise ValueError('la validación cruzada no generó predicciones para todas las filas')
    return probabilidades, metricas_folds


def _ajustar_calibradores(probabilidades, etiquetas):
    return {
        clase: LogisticRegression(random_state=SEMILLA_EVALUACION).fit(
            probabilidades[:, indice].reshape(-1, 1), (etiquetas == clase).astype(int))
        for indice, clase in enumerate(CLASES)
    }


def _calibrar(probabilidades, calibradores):
    calibradas = np.column_stack([
        calibradores[clase].predict_proba(probabilidades[:, indice].reshape(-1, 1))[:, 1]
        for indice, clase in enumerate(CLASES)
    ])
    totales = calibradas.sum(axis=1, keepdims=True)
    if np.any(totales <= 0):
        raise ValueError('la calibración produjo probabilidades sin masa')
    return calibradas / totales


def _brier_por_clase(probabilidades, etiquetas):
    por_clase = {
        clase: float(brier_score_loss((etiquetas == clase).astype(int), probabilidades[:, indice]))
        for indice, clase in enumerate(CLASES)
    }
    return {'por_clase': por_clase, 'promedio_por_clase': float(np.mean(list(por_clase.values())))}


def _curvas_confiabilidad(probabilidades, etiquetas, numero_bins=5):
    curvas = {}
    bordes = np.linspace(0, 1, numero_bins + 1)
    for indice, clase in enumerate(CLASES):
        verdadero = (etiquetas == clase).astype(int)
        probabilidades_clase = probabilidades[:, indice]
        bins = np.minimum(np.digitize(probabilidades_clase, bordes[1:-1]), numero_bins - 1)
        curvas[clase] = []
        for numero, (inferior, superior) in enumerate(zip(bordes[:-1], bordes[1:])):
            dentro = bins == numero
            if dentro.any():
                curvas[clase].append({
                    'intervalo': [float(inferior), float(superior)],
                    'confianza_media': float(probabilidades_clase[dentro].mean()),
                    'frecuencia_observada': float(verdadero[dentro].mean()),
                    'soporte': int(dentro.sum()),
                })
    return curvas


def _intervalo_bootstrap_grupos(etiquetas, predichas, grupos):
    rng = np.random.default_rng(SEMILLA_EVALUACION)
    grupos = np.asarray(grupos)
    unicos = np.unique(grupos)
    indices_por_grupo = {grupo: np.flatnonzero(grupos == grupo) for grupo in unicos}
    valores = []
    for _ in range(NUM_BOOTSTRAPS):
        muestra = rng.choice(unicos, size=len(unicos), replace=True)
        indices = np.concatenate([indices_por_grupo[grupo] for grupo in muestra])
        valores.append(f1_score(
            etiquetas[indices], predichas[indices], labels=CLASES, average='macro', zero_division=0))
    inferior, superior = np.quantile(valores, [0.025, 0.975])
    return {
        'metodo': 'bootstrap percentil por plantilla',
        'repeticiones': NUM_BOOTSTRAPS,
        'plantillas': int(len(unicos)),
        'nivel': 0.95,
        'inferior': float(inferior),
        'superior': float(superior),
    }


def entrenar(dataset_path=DATASET):
    """Entrena solo con la partición de entrenamiento y mide las dos líneas base en prueba."""
    dataset_path = Path(dataset_path)
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

    probabilidades_oof, folds = _probabilidades_oof(entrenamiento)
    calibradores = _ajustar_calibradores(probabilidades_oof, entrenamiento['etiqueta'].to_numpy())
    pipeline = crear_pipeline()
    pipeline.fit(entrenamiento[list(CARACTERISTICAS)], entrenamiento['etiqueta'])
    probabilidades_sin_calibrar = _probabilidades_alineadas(pipeline, prueba[list(CARACTERISTICAS)])
    probabilidades = _calibrar(probabilidades_sin_calibrar, calibradores)
    predichas = np.asarray(CLASES)[probabilidades.argmax(axis=1)]
    predichas_sin_calibrar = np.asarray(CLASES)[probabilidades_sin_calibrar.argmax(axis=1)]
    clases = _clases_presentes(dataset)
    metricas_modelo = _metricas(prueba['etiqueta'], predichas, clases)
    metricas_modelo_sin_calibrar = _metricas(prueba['etiqueta'], predichas_sin_calibrar, clases)
    caracteristicas_sin_sensibilidad = tuple(
        columna for columna in CARACTERISTICAS if columna != 'sensibilidad')
    _, folds_sin_sensibilidad = _probabilidades_oof(entrenamiento, caracteristicas_sin_sensibilidad)
    pipeline_sin_sensibilidad = crear_pipeline(caracteristicas_sin_sensibilidad)
    pipeline_sin_sensibilidad.fit(
        entrenamiento[list(caracteristicas_sin_sensibilidad)], entrenamiento['etiqueta'])
    probabilidades_sin_sensibilidad = _probabilidades_alineadas(
        pipeline_sin_sensibilidad, prueba[list(caracteristicas_sin_sensibilidad)])
    predichas_sin_sensibilidad = np.asarray(CLASES)[probabilidades_sin_sensibilidad.argmax(axis=1)]
    f1_sin_sensibilidad = float(f1_score(
        prueba['etiqueta'], predichas_sin_sensibilidad, labels=CLASES,
        average='macro', zero_division=0))
    f1_reglas = float(f1_score(prueba['etiqueta'], prueba['clase_reglas'], labels=clases,
                               average='macro', zero_division=0))
    f1_sensibilidad = float(f1_score(prueba['etiqueta'], prueba['sensibilidad'], labels=clases,
                                     average='macro', zero_division=0))
    supera_reglas = metricas_modelo['macro_f1'] > f1_reglas
    etiquetas_prueba = prueba['etiqueta'].to_numpy()
    metricas_calibracion = {
        'metodo': 'regresión logística one-vs-rest ajustada con probabilidades OOF agrupadas por plantilla',
        'particiones_oof': NUM_SPLITS,
        'brier_sin_calibrar': _brier_por_clase(probabilidades_sin_calibrar, etiquetas_prueba),
        'brier_calibrado': _brier_por_clase(probabilidades, etiquetas_prueba),
        'curva_confiabilidad_sin_calibrar': _curvas_confiabilidad(
            probabilidades_sin_calibrar, etiquetas_prueba),
        'curva_confiabilidad_calibrada': _curvas_confiabilidad(probabilidades, etiquetas_prueba),
    }
    predichas_array = np.asarray(predichas)
    metricas_cv = {
        'metodo': 'StratifiedGroupKFold',
        'grupos': 'plantilla',
        'particiones': NUM_SPLITS,
        'semilla': SEMILLA_EVALUACION,
        'folds': folds,
        'macro_f1_media': float(np.mean([fold['macro_f1'] for fold in folds])),
        'macro_f1_desviacion_estandar': float(np.std([fold['macro_f1'] for fold in folds])),
    }
    metricas = {
        'version': VERSION,
        'algoritmo': 'ExtraTreesClassifier',
        'dataset': 'datos/ml/rc65/dataset.csv',
        'dataset_sha256': hashlib.sha256(dataset_path.read_bytes()).hexdigest(),
        'origen_etiquetas': 'LLM; sin validación humana',
        'caracteristicas': list(CARACTERISTICAS),
        'codigos_entrenados': sorted(CODIGOS_ENTRENADOS),
        'particionamiento': 'por_plantilla',
        'filas_entrenamiento': int(len(entrenamiento)),
        'filas_prueba': int(len(prueba)),
        'lineas_base': {'reglas_macro_f1': f1_reglas, 'sensibilidad_macro_f1': f1_sensibilidad},
        'modelo': metricas_modelo,
        'modelo_sin_calibrar': metricas_modelo_sin_calibrar,
        'ablacion_sensibilidad': {
            'caracteristicas': list(caracteristicas_sin_sensibilidad),
            'macro_f1_prueba': f1_sin_sensibilidad,
            'delta_macro_f1_prueba': (
                f1_sin_sensibilidad - metricas_modelo_sin_calibrar['macro_f1']),
            'macro_f1_cv_media': float(np.mean([fold['macro_f1'] for fold in folds_sin_sensibilidad])),
            'macro_f1_cv_desviacion_estandar': float(
                np.std([fold['macro_f1'] for fold in folds_sin_sensibilidad])),
        },
        'validacion_cruzada': metricas_cv,
        'bootstrap_macro_f1_prueba': _intervalo_bootstrap_grupos(
            etiquetas_prueba, predichas_array, prueba['plantilla'].to_numpy()),
        'calibracion': metricas_calibracion,
        'supera_reglas': supera_reglas,
        'supera_sensibilidad': metricas_modelo['macro_f1'] > f1_sensibilidad,
        'integrable': supera_reglas,
    }
    return {'version': VERSION, 'pipeline': pipeline, 'calibradores': calibradores, 'metrics': metricas}


def _clases_presentes(dataset):
    return sorted(set(dataset['etiqueta']))


def guardar(bundle, artefacto=ARTEFACTO, ficha=FICHA, huella=None):
    """Escribe el modelo, su sha256 junto a él y la ficha con ese sha256.

    La huella va en cirdan/ml/ (modelo_v1.joblib.sha256), que entra en la imagen, y es la que revisa
    inferencia.cargar_modelo antes de cargar. docs/ no entra en la imagen (RC-305).
    """
    huella = huella or artefacto.with_name(artefacto.name + '.sha256')
    artefacto.parent.mkdir(parents=True, exist_ok=True)
    ficha.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, artefacto, compress=3)
    sha256 = hashlib.sha256(artefacto.read_bytes()).hexdigest()
    huella.write_text('%s  %s\n' % (sha256, artefacto.name), encoding='ascii', newline='\n')
    ficha.write_text(json.dumps({**bundle['metrics'], 'sha256': sha256}, ensure_ascii=False, indent=2) + '\n',
                     encoding='utf-8', newline='\n')
    return sha256


def main():
    bundle = entrenar()
    guardar(bundle)
    print(json.dumps(bundle['metrics'], ensure_ascii=False, indent=2))
    print('Modelo guardado en %s' % ARTEFACTO.relative_to(RAIZ))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
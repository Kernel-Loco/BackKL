"""Detector experimental de perfiles raros entre hallazgos de alto riesgo (#67)."""
import hashlib
import io
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from cirdan.ml.modelo import (
    CARACTERISTICAS,
    CARACTERISTICAS_CATEGORICAS,
    CARACTERISTICAS_NUMERICAS,
    DATASET,
    RAIZ,
)

VERSION = 'v1-anomalias-rc67-1'
ARTEFACTO = Path(__file__).with_name('modelo_anomalias_v1.joblib')
HUELLA = Path(__file__).with_name('modelo_anomalias_v1.joblib.sha256')
FICHA = RAIZ / 'docs' / 'modelo_anomalias_v1.json'
SEVERIDADES_ALTO_RIESGO = frozenset(('critical', 'high'))


def crear_pipeline():
    preprocesador = ColumnTransformer(
        [
            ('categoricas', OneHotEncoder(handle_unknown='ignore'), list(CARACTERISTICAS_CATEGORICAS)),
            ('numericas', StandardScaler(), list(CARACTERISTICAS_NUMERICAS)),
        ],
        verbose_feature_names_out=False,
    )
    detector = IsolationForest(
        n_estimators=300, contamination='auto', random_state=67, n_jobs=1)
    return make_pipeline(preprocesador, detector)


def entrenar(dataset_path=DATASET):
    dataset_path = Path(dataset_path)
    dataset = pd.read_csv(dataset_path)
    requeridas = (*CARACTERISTICAS, 'etiqueta', 'particion', 'plantilla')
    if any(columna not in dataset.columns for columna in requeridas):
        raise ValueError('faltan columnas de características, etiquetas o partición en el dataset')
    entrenamiento = dataset[
        (dataset['particion'] == 'entrenamiento') & (dataset['etiqueta'] == 'alta')
    ]
    if entrenamiento.empty:
        raise ValueError('se necesitan perfiles de alto riesgo en entrenamiento')

    pipeline = crear_pipeline()
    pipeline.fit(entrenamiento[list(CARACTERISTICAS)])
    metricas = {
        'version': VERSION,
        'algoritmo': 'IsolationForest',
        'dataset': 'datos/ml/rc65/dataset.csv',
        'dataset_sha256': hashlib.sha256(dataset_path.read_bytes()).hexdigest(),
        'origen_etiquetas': 'LLM; sin validación humana',
        'caracteristicas': list(CARACTERISTICAS),
        'criterio_entrenamiento': 'etiqueta alta en la partición de entrenamiento',
        'filas_entrenamiento': int(len(entrenamiento)),
        'plantillas_entrenamiento': sorted(entrenamiento['plantilla'].unique()),
        'contamination': 'auto',
        'salida': 'score continuo; valores mayores indican perfiles más raros',
        'umbral': None,
        'validacion_anomalias': 'no disponible: no hay etiquetas de anomalía ni validación humana',
        'afecta_severidad_o_score': False,
    }
    return {'version': VERSION, 'pipeline': pipeline, 'metrics': metricas}


def puntuar(bundle, hallazgos):
    """Devuelve scores continuos solo para hallazgos high/critical; no fija umbral ni altera el score."""
    elegibles = [hallazgo for hallazgo in hallazgos
                 if hallazgo.get('severity') in SEVERIDADES_ALTO_RIESGO]
    if not elegibles:
        return {}
    caracteristicas = []
    for hallazgo in elegibles:
        datos = hallazgo.get('caracteristicas')
        if not isinstance(datos, dict) or any(campo not in datos for campo in CARACTERISTICAS):
            raise ValueError('cada hallazgo elegible debe incluir las cuatro características ML')
        caracteristicas.append(datos)
    entrada = pd.DataFrame(caracteristicas, columns=CARACTERISTICAS)
    scores = -bundle['pipeline'].decision_function(entrada)
    return {hallazgo['id']: float(score) for hallazgo, score in zip(elegibles, scores)}


def guardar(bundle, artefacto=ARTEFACTO, ficha=FICHA, huella=None):
    huella = huella or artefacto.with_name(artefacto.name + '.sha256')
    artefacto.parent.mkdir(parents=True, exist_ok=True)
    ficha.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, artefacto, compress=3)
    sha256 = hashlib.sha256(artefacto.read_bytes()).hexdigest()
    huella.write_text('%s  %s\n' % (sha256, artefacto.name), encoding='ascii', newline='\n')
    ficha.write_text(json.dumps({**bundle['metrics'], 'sha256': sha256}, ensure_ascii=False, indent=2) + '\n',
                     encoding='utf-8', newline='\n')
    return sha256


def cargar_modelo(ruta=ARTEFACTO, huella=HUELLA):
    datos = Path(ruta).read_bytes()
    partes = Path(huella).read_text(encoding='ascii').split()
    if not partes or len(partes[0]) != 64 or any(c not in '0123456789abcdef' for c in partes[0]):
        raise ValueError('la huella del detector no es un sha256')
    calculada = hashlib.sha256(datos).hexdigest()
    if calculada != partes[0]:
        raise ValueError('la huella del detector no coincide')
    return joblib.load(io.BytesIO(datos))


def main():
    bundle = entrenar()
    guardar(bundle)
    print(json.dumps(bundle['metrics'], ensure_ascii=False, indent=2))
    print('Detector guardado en %s' % ARTEFACTO.relative_to(RAIZ))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

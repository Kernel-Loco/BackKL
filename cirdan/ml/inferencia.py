"""Inferencia ML y valores SHAP por hallazgo (#35, #36)."""
from functools import lru_cache
import os
from pathlib import Path

ARTEFACTO = Path(__file__).with_name('modelo_v1.joblib')
CLASE_A_SEVERIDAD = {'alta': 'high', 'media': 'medium', 'baja': 'low'}
CARACTERISTICAS_CATEGORICAS = ('tipo', 'exposicion', 'sensibilidad')


@lru_cache(maxsize=1)
def cargar_modelo(ruta=None):
    import joblib

    ruta = Path(ruta or os.environ.get('CIRDAN_ML_MODEL_PATH', ARTEFACTO))
    return joblib.load(ruta)


def predecir(bundle, filas):
    """Predice severidad, confianza y los 3 SHAP de mayor magnitud por hallazgo."""
    import numpy as np
    import pandas as pd
    import shap

    from cirdan.ml.caracteristicas import calcular as calcular_caracteristicas
    from cirdan.ml.modelo import CARACTERISTICAS, CARACTERISTICAS_CATEGORICAS
    from datetime import date

    if not filas:
        return {}
    caracteristicas = []
    for fila in filas:
        datos = fila.get('caracteristicas')
        if not isinstance(datos, dict) or any(campo not in datos for campo in CARACTERISTICAS):
            referencia = fila.get('scan_at') or fila.get('detected_at') or date.today()
            datos = calcular_caracteristicas(
                fila['rule_code'], fila['asset_type'], fila.get('evidence') or {}, referencia,
                detectado=fila.get('detected_at'), activo_visto=fila.get('asset_first_seen'),
            )
        caracteristicas.append(datos)

    entrada = pd.DataFrame(caracteristicas, columns=CARACTERISTICAS)
    pipeline = bundle['pipeline']
    predichas = pipeline.predict(entrada)
    probabilidades = pipeline.predict_proba(entrada)
    clases = list(pipeline.classes_)

    preprocesador = pipeline.named_steps['columntransformer']
    clasificador = pipeline.named_steps['extratreesclassifier']
    matriz = preprocesador.transform(entrada)
    if hasattr(matriz, 'toarray'):
        matriz = matriz.toarray()
    matriz = np.asarray(matriz, dtype=float)
    valores = shap.TreeExplainer(clasificador).shap_values(matriz)
    if isinstance(valores, list):
        valores = np.stack(valores, axis=-1)
    valores = np.asarray(valores)
    if valores.ndim == 2:
        valores = valores[:, :, None]
    if valores.ndim != 3 or valores.shape[0] != len(filas):
        raise ValueError('forma SHAP inesperada: %s' % (valores.shape,))
    if valores.shape[1] != matriz.shape[1] and valores.shape[2] == matriz.shape[1]:
        valores = valores.transpose(0, 2, 1)
    if valores.shape[1] != matriz.shape[1]:
        raise ValueError('número de características SHAP inesperado: %s' % (valores.shape,))

    codificador = preprocesador.named_transformers_['categoricas']
    grupos = {}
    inicio = 0
    for feature, categorias in zip(CARACTERISTICAS_CATEGORICAS, codificador.categories_):
        fin = inicio + len(categorias)
        grupos[feature] = slice(inicio, fin)
        inicio = fin
    for feature in CARACTERISTICAS:
        if feature not in grupos:
            grupos[feature] = slice(inicio, inicio + 1)
            inicio += 1
    if inicio != valores.shape[1]:
        raise ValueError('el preprocesador produjo características inesperadas')

    resultado = {}
    for i, fila in enumerate(filas):
        clase = str(predichas[i])
        clase_index = clases.index(clase)
        aportes = [
            {'feature': feature, 'value': caracteristicas[i][feature],
             'contribution': float(valores[i, indices, clase_index].sum())}
            for feature, indices in grupos.items()
        ]
        aportes.sort(key=lambda aporte: abs(aporte['contribution']), reverse=True)
        severidad = 'critical' if fila['severity'] == 'critical' else CLASE_A_SEVERIDAD[clase]
        resultado[fila['id']] = {
            'severity': severidad,
            'confidence': float(probabilidades[i, clase_index]),
            'shap': aportes[:3],
        }
    return resultado
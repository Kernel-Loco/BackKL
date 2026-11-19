"""Inferencia ML y valores SHAP por hallazgo (#35, #36)."""
from functools import lru_cache
import hashlib
import io
import logging
import re
from pathlib import Path

ARTEFACTO = Path(__file__).with_name('modelo_v1.joblib')
# sha256 del artefacto, escrito por modelo.guardar. Vive en cirdan/ porque docs/ no entra en la imagen (RC-305)
HUELLA = Path(__file__).with_name('modelo_v1.joblib.sha256')
CLASE_A_SEVERIDAD = {'alta': 'high', 'media': 'medium', 'baja': 'low'}
CARACTERISTICAS_CATEGORICAS = ('tipo', 'exposicion', 'sensibilidad')

log = logging.getLogger(__name__)


class HuellaNoCoincide(ValueError):
    """El sha256 del artefacto no es el de cirdan/ml/modelo_v1.joblib.sha256: no se carga."""


def leer_huella(huella=HUELLA):
    """Lee el sha256 del archivo de huella, con la forma de sha256sum: '<hex>  modelo_v1.joblib'."""
    try:
        partes = Path(huella).read_text(encoding='ascii').split()
    except FileNotFoundError:
        # Sin huella el modelo no se carga. cargar_modelo ya leyó el artefacto, así que no es 'artefacto_ml_no_disponible'
        log.warning('Falta la huella del modelo %s. No se carga.', Path(huella).name)
        raise HuellaNoCoincide('falta la huella del modelo %s' % Path(huella).name) from None
    if not partes or not re.fullmatch(r'[0-9a-f]{64}', partes[0]):
        raise HuellaNoCoincide('la huella del modelo en %s no es un sha256' % Path(huella).name)
    return partes[0]


@lru_cache(maxsize=1)
def cargar_modelo(ruta=ARTEFACTO, huella=HUELLA):
    """Carga el modelo solo si su sha256 es el de la huella: joblib.load lee un pickle, que puede ejecutar código.

    Se lee el archivo una vez y se carga de esos mismos bytes, así no se puede cambiar entre la revisión y la carga.
    """
    import joblib

    datos = Path(ruta).read_bytes()
    esperada = leer_huella(huella)
    calculada = hashlib.sha256(datos).hexdigest()
    if calculada != esperada:
        log.warning('La huella del modelo %s no coincide: sha256 %s, se esperaba %s. No se carga.',
                    Path(ruta).name, calculada, esperada)
        raise HuellaNoCoincide('la huella del modelo %s no coincide' % Path(ruta).name)
    return joblib.load(io.BytesIO(datos))


def predecir_probabilidades(bundle, entrada):
    """Devuelve las clases del artefacto y probabilidades calibradas en el mismo orden."""
    import numpy as np

    pipeline = bundle['pipeline']
    probabilidades = pipeline.predict_proba(entrada)
    clases = list(pipeline.classes_)
    calibradores = bundle.get('calibradores')
    if calibradores:
        probabilidades = np.column_stack([
            calibradores[clase].predict_proba(probabilidades[:, indice].reshape(-1, 1))[:, 1]
            for indice, clase in enumerate(clases)
        ])
        totales = probabilidades.sum(axis=1, keepdims=True)
        if np.any(totales <= 0):
            raise ValueError('la calibración produjo probabilidades sin masa')
        probabilidades /= totales
    return clases, probabilidades


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
    codigos_entrenados = frozenset(bundle.get('metrics', {}).get('codigos_entrenados', ()))
    filas = [fila for fila in filas if fila.get('rule_code') in codigos_entrenados]
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
    clases, probabilidades = predecir_probabilidades(bundle, entrada)
    predichas = np.asarray(clases)[probabilidades.argmax(axis=1)]

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
        prediccion_ml = CLASE_A_SEVERIDAD[clase]
        aportes = [
            {'feature': feature, 'value': caracteristicas[i][feature],
             'contribution': float(valores[i, indices, clase_index].sum())}
            for feature, indices in grupos.items()
        ]
        aportes.sort(key=lambda aporte: abs(aporte['contribution']), reverse=True)
        severidad = 'critical' if fila['severity'] == 'critical' else CLASE_A_SEVERIDAD[clase]
        resultado[fila['id']] = {
            'severity': severidad,
            'model_prediction': prediccion_ml,
            'confidence': float(probabilidades[i, clase_index]),
            'shap': aportes[:3],
        }
    return resultado
"""Carga diaria de CISA KEV y FIRST EPSS, sin cambiar severidades ni scores."""
import csv
import gzip
import io
import json
import re
import time
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from urllib.request import Request

import psycopg
from psycopg.conninfo import make_conninfo

from cirdan.config import config, required
from cirdan.recolectores import transporte

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}', re.ASCII)
_EPSS_DESTINO = re.compile(r'https://epss\.empiricalsecurity\.com/epss_scores-[0-9]{4}-[0-9]{2}-[0-9]{2}\.csv\.gz', re.ASCII)
CANDADO = 'cirdan.inteligencia'


def descargar_json(url, tope):
    req = Request(url, headers={'User-Agent': 'lowtide-osint', 'Accept': 'application/json'})
    return json.loads(transporte.descargar(req, time.monotonic() + 60, tope))


def descargar_epss():
    req = Request(EPSS_URL, headers={'User-Agent': 'lowtide-osint'})
    try:
        return transporte.descargar(req, time.monotonic() + 120, 50 * 1024 * 1024)
    except transporte.Redirigida as redireccion:
        if not redireccion.destino or not _EPSS_DESTINO.fullmatch(redireccion.destino):
            raise ValueError('destino de EPSS inesperado') from redireccion
        req = Request(redireccion.destino, headers={'User-Agent': 'lowtide-osint'})
        return transporte.descargar(req, time.monotonic() + 120, 50 * 1024 * 1024)


def leer_kev(datos):
    if not isinstance(datos, dict) or not isinstance(datos.get('vulnerabilities'), list):
        raise ValueError('catálogo KEV inválido')
    entradas = datos['vulnerabilities']
    if not entradas or type(datos.get('count')) is not int or datos['count'] != len(entradas):
        raise ValueError('catálogo KEV vacío o incompleto')
    resultado = {}
    for entrada in entradas:
        if not isinstance(entrada, dict):
            raise ValueError('entrada KEV inválida')
        cve, fecha = entrada.get('cveID'), entrada.get('dateAdded')
        if not isinstance(cve, str) or not _CVE.fullmatch(cve) or cve in resultado:
            raise ValueError('CVE inválida o repetida en KEV')
        try:
            resultado[cve] = date.fromisoformat(fecha)
        except (ValueError, TypeError):
            raise ValueError('fecha KEV inválida para %s' % cve) from None
    return resultado


def _probabilidad(valor):
    if not isinstance(valor, str):
        raise ValueError('probabilidad EPSS inválida')
    try:
        numero = Decimal(valor)
    except InvalidOperation:
        raise ValueError('probabilidad EPSS inválida') from None
    if not numero.is_finite() or not 0 <= numero <= 1:
        raise ValueError('probabilidad EPSS fuera de rango')
    return numero


def leer_epss(comprimido, solicitados, hoy=None):
    with gzip.GzipFile(fileobj=io.BytesIO(comprimido)) as archivo:
        contenido = archivo.read(150 * 1024 * 1024 + 1)
    if len(contenido) > 150 * 1024 * 1024:
        raise ValueError('archivo EPSS descomprimido demasiado grande')
    texto = io.StringIO(contenido.decode('utf-8'), newline='')
    cabecera = texto.readline().strip()
    fecha = re.search(r'(?:^|,)score_date:([0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)?)(?:,|$)',
                      cabecera.lstrip('#'))
    if not fecha:
        raise ValueError('archivo EPSS sin fecha')
    dia = datetime.fromisoformat(fecha.group(1).replace('Z', '+00:00')).date()
    hoy = hoy or datetime.now(timezone.utc).date()
    if dia > hoy or hoy - dia > timedelta(days=3):
        raise ValueError('archivo EPSS desactualizado o con fecha futura')
    lector = csv.DictReader(texto)
    if lector.fieldnames != ['cve', 'epss', 'percentile']:
        raise ValueError('columnas EPSS inválidas')
    resultado = {}
    vistos = set()
    for fila in lector:
        cve = fila.get('cve')
        if not isinstance(cve, str) or not _CVE.fullmatch(cve) or cve in vistos or None in fila:
            raise ValueError('CVE inválida o repetida en EPSS')
        vistos.add(cve)
        puntajes = (_probabilidad(fila.get('epss')), _probabilidad(fila.get('percentile')))
        if cve in solicitados:
            resultado[cve] = puntajes
    if not vistos:
        raise ValueError('archivo EPSS vacío')
    return resultado


def conexion():
    return psycopg.connect(make_conninfo(host=config('PGHOST', '127.0.0.1'), port=config('PGPORT', '5433'),
                                         dbname=config('PGDATABASE', 'cirdan'), user='cirdan_intel',
                                         password=required('CIRDAN_INTEL_PASSWORD')), autocommit=True)


def actualizar(conn, obtener_kev=descargar_json, obtener_epss=descargar_epss):
    """Descarga y valida todo antes de reemplazar la inteligencia en una transacción."""
    if not conn.execute('SELECT pg_try_advisory_lock(hashtext(%s), 0)', (CANDADO,)).fetchone()[0]:
        raise RuntimeError('otro cargador de inteligencia está en ejecución')
    try:
        existentes = {fila[0] for fila in conn.execute('SELECT cve_id FROM public.cves')}
        kev = leer_kev(obtener_kev(KEV_URL, 10 * 1024 * 1024))
        ids = sorted(existentes | set(kev))
        epss = leer_epss(obtener_epss(), set(ids))
        with conn.transaction():
            with conn.cursor() as cursor:
                cursor.executemany('''
                    INSERT INTO public.cves
                      (cve_id, epss_score, epss_percentile, in_kev, kev_date_added, intel_updated_at)
                    VALUES (%s, %s, %s, %s, %s, now())
                    ON CONFLICT (cve_id) DO UPDATE SET
                      epss_score = EXCLUDED.epss_score, epss_percentile = EXCLUDED.epss_percentile,
                      in_kev = EXCLUDED.in_kev, kev_date_added = EXCLUDED.kev_date_added,
                      intel_updated_at = EXCLUDED.intel_updated_at, updated_at = now()
                ''', [(cve, *epss.get(cve, (None, None)), cve in kev, kev.get(cve)) for cve in ids])
        return len(ids), len(kev), len(epss)
    finally:
        conn.execute('SELECT pg_advisory_unlock(hashtext(%s), 0)', (CANDADO,))

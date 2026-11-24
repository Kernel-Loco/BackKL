#!/usr/bin/env python3
"""Comprueba que cada carta referenciada por la base restaurada abre y coincide con su huella.

Cada fila de referencias.tsv es organization_id|id del AAD|llave|huella en hex. El id del AAD es el que usó
cirdan/cartas.py al cifrar: el domain_id en las cartas subidas a mano (RC-59 y camino A de Mifiel) y el id de la
solicitud en las que salieron de la API de Mifiel (signature_requests, RC-211). Una misma llave puede venir de
signature_requests y de domain_authorizations: vale si las dos filas dicen lo mismo.

Las llaves de las semillas (authorizations/..., también las que cambian las pruebas) son de antes del alta y
nunca tuvieron archivo en el volumen: se cuentan y se reportan, sin abortar. Cualquier otra llave que no sea <32 hex>.lt1 aborta.
"""
import base64
import binascii
import hashlib
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

PATRON = re.compile(r'[0-9a-f]{32}\.lt1\Z')
PATRON_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
PATRON_ANTERIOR = re.compile(r'authorizations/[A-Za-z0-9._/-]+\Z')


def main():
    if len(sys.argv) != 4:
        raise SystemExit('uso: verificar_cartas.py <llave> <referencias.tsv> <directorio>')
    llave_path, referencias_path, directorio = map(Path, sys.argv[1:])
    try:
        llave = base64.b64decode(llave_path.read_bytes().strip(), altchars=b'-_', validate=True)
    except (ValueError, binascii.Error):
        raise SystemExit('la llave recuperada no es válida') from None
    if len(llave) != 32:
        raise SystemExit('la llave recuperada no tiene 32 bytes')

    filas = referencias_path.read_text(encoding='ascii').splitlines()
    aes = AESGCM(llave)
    vistos = {}
    anteriores = set()
    for fila in filas:
        partes = fila.split('|')
        if len(partes) != 4:
            raise SystemExit('la lista de referencias no es válida')
        organizacion, dominio, nombre, huella = partes
        if PATRON_ANTERIOR.fullmatch(nombre) and '..' not in nombre:
            anteriores.add(nombre)
            continue
        if (not PATRON.fullmatch(nombre) or not PATRON_UUID.fullmatch(organizacion)
                or not PATRON_UUID.fullmatch(dominio) or not re.fullmatch(r'[0-9a-f]{64}', huella)):
            raise SystemExit('una referencia de carta no es válida')
        if nombre in vistos:
            if vistos[nombre] != (organizacion, dominio, huella):
                raise SystemExit('dos registros de la base citan la misma carta con datos distintos')
            continue
        vistos[nombre] = (organizacion, dominio, huella)
        archivo = directorio / nombre
        if archivo.is_symlink() or not archivo.is_file():
            raise SystemExit('falta una carta referenciada en el volumen restaurado')
        blob = archivo.read_bytes()
        if len(blob) < 31 or not blob.startswith(b'LT1'):
            raise SystemExit('una carta restaurada tiene formato inválido')
        try:
            pdf = aes.decrypt(blob[3:15], blob[15:], ('%s:%s:%s' % (organizacion, dominio, nombre)).encode('utf-8'))
        except InvalidTag:
            raise SystemExit('una carta no autentica con la llave y el dominio o la solicitud restaurados') from None
        if hashlib.sha256(pdf).hexdigest() != huella:
            raise SystemExit('la huella de una carta restaurada no coincide')
    print('verificar_cartas: %d cartas referenciadas verificadas' % len(vistos))
    if anteriores:
        print('verificar_cartas: %d llaves sin archivo (anteriores al alta)' % len(anteriores))


if __name__ == '__main__':
    main()

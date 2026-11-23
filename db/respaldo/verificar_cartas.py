#!/usr/bin/env python3
"""Comprueba que cada carta referenciada por la base restaurada abre y coincide con su huella."""
import base64
import binascii
import hashlib
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

PATRON = re.compile(r'[0-9a-f]{32}\.lt1\Z')


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
    vistos = set()
    for fila in filas:
        partes = fila.split('|')
        if len(partes) != 4:
            raise SystemExit('la lista de referencias no es válida')
        organizacion, dominio, nombre, huella = partes
        if not PATRON.fullmatch(nombre) or nombre in vistos or not re.fullmatch(r'[0-9a-f]{64}', huella):
            raise SystemExit('una referencia de carta no es válida')
        vistos.add(nombre)
        archivo = directorio / nombre
        if archivo.is_symlink() or not archivo.is_file():
            raise SystemExit('falta una carta referenciada en el volumen restaurado')
        blob = archivo.read_bytes()
        if len(blob) < 31 or not blob.startswith(b'LT1'):
            raise SystemExit('una carta restaurada tiene formato inválido')
        try:
            pdf = aes.decrypt(blob[3:15], blob[15:], ('%s:%s:%s' % (organizacion, dominio, nombre)).encode('utf-8'))
        except InvalidTag:
            raise SystemExit('una carta no autentica con la llave y el dominio restaurados') from None
        if hashlib.sha256(pdf).hexdigest() != huella:
            raise SystemExit('la huella de una carta restaurada no coincide')
    print('verificar_cartas: %d cartas referenciadas verificadas' % len(vistos))


if __name__ == '__main__':
    main()

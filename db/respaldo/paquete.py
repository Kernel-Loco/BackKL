#!/usr/bin/env python3
"""Empaqueta y extrae respaldos de cartas sin confiar en nombres de un archivo tar."""
import argparse
import base64
import binascii
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path

ARCHIVOS_PAQUETE = ('cirdan.dump.age', 'cartas.tar.age', 'carta.key.age')
PATRON_CARTA = re.compile(r'[0-9a-f]{32}\.lt1\Z')
# El archivo más grande que guarda cirdan/cartas.py es el que baja Mifiel (TOPE_ARCHIVO de cirdan/firma/mifiel.py,
# 25 MiB), por encima de la carta subida (5 MiB) y del XML de evidencia (7 MB). LT1, nonce y etiqueta suman 31 bytes.
MAX_CARTA = 25 * 1024 * 1024 + 31


def _copiar_miembro(archivo, miembro, destino):
    fd = os.open(destino, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as salida, archivo.extractfile(miembro) as entrada:
        if entrada is None:
            raise ValueError('miembro tar sin contenido')
        shutil.copyfileobj(entrada, salida)
        salida.flush()
        os.fsync(salida.fileno())


def extraer_paquete(archivo, destino):
    destino = Path(destino)
    with tarfile.open(archivo, mode='r:') as tar:
        miembros = tar.getmembers()
        nombres = [miembro.name for miembro in miembros]
        if len(nombres) != len(ARCHIVOS_PAQUETE) or set(nombres) != set(ARCHIVOS_PAQUETE):
            raise ValueError('el paquete debe contener exactamente los tres archivos de respaldo')
        if sum(miembro.size for miembro in miembros) > shutil.disk_usage(destino).free:
            raise ValueError('no hay espacio temporal suficiente para extraer el paquete')
        for miembro in miembros:
            if not miembro.isfile():
                raise ValueError('el paquete contiene un tipo de archivo no permitido')
            _copiar_miembro(tar, miembro, destino / miembro.name)


def extraer_cartas(archivo, destino):
    destino = Path(destino)
    vistos = set()
    with tarfile.open(archivo, mode='r:') as tar:
        miembros = tar.getmembers()
        if sum(miembro.size for miembro in miembros) > shutil.disk_usage(destino).free:
            raise ValueError('no hay espacio temporal suficiente para extraer las cartas')
        for miembro in miembros:
            if (not miembro.isfile() or not PATRON_CARTA.fullmatch(miembro.name)
                    or miembro.name in vistos or not 31 <= miembro.size <= MAX_CARTA):
                raise ValueError('el archivo de cartas contiene una entrada no válida')
            vistos.add(miembro.name)
            _copiar_miembro(tar, miembro, destino / miembro.name)
    descriptor = os.open(destino, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def crear_paquete(directorio):
    directorio = Path(directorio)
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as tar:
        for nombre in ARCHIVOS_PAQUETE:
            ruta = directorio / nombre
            if not ruta.is_file() or ruta.is_symlink():
                raise ValueError('falta un archivo cifrado del paquete')
            tar.add(ruta, arcname=nombre, recursive=False)


def validar_llave(ruta):
    try:
        valor = Path(ruta).read_text(encoding='ascii').strip()
        llave = base64.b64decode(valor.encode('ascii'), altchars=b'-_', validate=True)
    except (UnicodeDecodeError, ValueError, binascii.Error):
        raise ValueError('la llave recuperada no es base64 url-safe válido') from None
    if len(llave) != 32:
        raise ValueError('la llave recuperada no tiene 32 bytes')


def main():
    parser = argparse.ArgumentParser()
    comandos = parser.add_subparsers(dest='comando', required=True)
    crear = comandos.add_parser('crear')
    crear.add_argument('directorio')
    extraer = comandos.add_parser('extraer')
    extraer.add_argument('archivo')
    extraer.add_argument('directorio')
    cartas = comandos.add_parser('cartas')
    cartas.add_argument('archivo')
    cartas.add_argument('directorio')
    llave = comandos.add_parser('llave')
    llave.add_argument('archivo')
    args = parser.parse_args()

    if args.comando == 'crear':
        crear_paquete(args.directorio)
    elif args.comando == 'extraer':
        extraer_paquete(args.archivo, args.directorio)
    elif args.comando == 'cartas':
        extraer_cartas(args.archivo, args.directorio)
    else:
        validar_llave(args.archivo)


if __name__ == '__main__':
    try:
        main()
    except (OSError, tarfile.TarError, ValueError) as error:
        print('paquete: ERROR: %s' % error, file=sys.stderr)
        raise SystemExit(1) from None

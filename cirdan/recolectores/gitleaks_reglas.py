"""Arma gitleaks_cirdan.toml, la config de gitleaks del recolector de GitHub (#16, RC-50), desde el binario de gitleaks.

Es la config por omisión que gitleaks trae embebida, copiada sin herencia y con tres cambios:
- CAMBIOS quita o ancla rutas de la lista global que se salta (paths de [allowlist]). La de 8.21.2 salta archivos que
  escribe el cliente: los lock files, todo lo que lleve 'gitleaks.toml' en la ruta y lo que termine en doc, bin o v2
  aunque no sea extensión, como guia.adoc, api/v2 o scripts/bin. CONSERVADAS se quedan como vienen: dependencias que
  instala un gestor de paquetes, como node_modules/, donde las claves de ejemplo de las librerías llenarían el reporte
  de hallazgos críticos, binarios, archivos generados donde las reglas dan falsos positivos, como go.sum, y las copias
  de jQuery y Swagger UI. Esa última también salta un archivo del cliente cuyo nombre empiece con jquery o swagger-ui.
- Se agrega la regla cirdan-fake-token. Ninguna de omisión halla un token CIRDAN_FAKE_: generic-api-key descarta los
  valores con la palabra 'fake' y el token sembrado en olmardo/sitio-reservas no tiene la forma de ningún proveedor.
- Cambian el encabezado y el título. El encabezado trae la licencia MIT de gitleaks, porque las reglas son suyas.
Se copia en vez de heredarla con [extend] useDefault porque en 8.21.2 la allowlist heredada se suma a la propia y no
se le puede quitar nada.

Al subir gitleaks se vuelve a generar dentro de la imagen nueva, desde la raíz de BackKL:
    docker compose run --rm -T --no-deps api python -m cirdan.recolectores.gitleaks_reglas \\
        > cirdan/recolectores/gitleaks_cirdan.toml
Falla si la lista de la versión nueva trae una ruta que no está en CAMBIOS ni en CONSERVADAS, o si le falta una de
CAMBIOS: hay que revisarla antes de copiarla. Integracion de pruebas/test_github.py falla si el archivo no es igual a
lo que esto genera con el gitleaks de la imagen.
"""
import re
import shutil
import struct
import subprocess
import sys

LICENCIA = '/usr/share/licenses/gitleaks/LICENSE'   # la deja el Dockerfile
MARCA = 'title = "gitleaks config"'                  # primera línea que no es comentario de la config embebida
TITULO = 'title = "LowTide: reglas de omisión de gitleaks y tokens falsos CIRDAN_FAKE_"'

# Ruta de la lista global de 8.21.2 -> la que la reemplaza, o None si se quita. Las que se quedan como vienen están
# en CONSERVADAS.
CAMBIOS = {
    # Archivos del cliente. En los lock files queda el token de una dependencia que se baja de un repo o un registro
    # privado (git+https://<token>@github.com/...). gitleaks.toml sin anclar salta cualquier ruta que lo lleve, como
    # deploy/gitleaks.toml/claves.env, y la config de gitleaks completa no da hallazgos con estas mismas reglas.
    r'gitleaks\.toml': None,
    r'(^|/)package-lock\.json$': None,
    r'(^|/)yarn\.lock$': None,
    r'(^|/)pnpm-lock\.yaml$': None,
    r'(^|/)npm-shrinkwrap\.json$': None,
    r'(^|/)(Pipfile|poetry)\.lock$': None,
    # Sin punto o sin inicio de carpeta saltaban más de lo que dicen: guia.adoc, api/v2, scripts/bin o
    # infra/prodenv/lib/ajustes.py. La de los entornos virtuales solo salta site-packages, así que una carpeta
    # .env/lib/ del cliente se revisa. Es el respaldo para un entorno subido sin su marca: con pyvenv.cfg o
    # conda-meta/, github.py descarta lo de sus paquetes sea cual sea su forma (fuera_de_entornos).
    r'(.*?)(doc|docx|zip|xls|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$':
        r'\.(doc|docx|zip|xls|pdf|bin|socket|vsidx|v2|suo|wsuo|dll|pdb|exe|gltf)$',
    r'(?i)/?(v?env|virtualenv)/lib(64)?/.+$':
        r'(?i)(^|/)\.?(v?env|virtualenv)/lib(64)?/((python|pypy)[23](\.\d{1,2})+t?/)?site-packages/.+$',
    r'go\.(mod|sum|work(\.sum)?)$': r'(^|/)go\.(mod|sum|work(\.sum)?)$',
    r'verification-metadata.xml': r'(^|/)verification-metadata\.xml$',
    r'Database.refactorlog': r'Database\.refactorlog$',
}

# Rutas de la lista global de 8.21.2 que se quedan como vienen.
CONSERVADAS = (
    r'(?i)\.(bmp|gif|jpe?g|svg|tiff?)$',
    r'\.(eot|[ot]tf|woff2?)$',
    r'(^|/)vendor/modules\.txt$',
    r'(^|/)vendor/(github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)/.*$',
    r'(^|/)gradlew(\.bat)?$',
    r'(^|/)gradle\.lockfile$',
    r'(^|/)mvnw(\.cmd)?$',
    r'(^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$',
    r'(^|/)node_modules/.*?$',
    r'(^|/)bower_components/.*?$',
    r'(^|/)(jquery(-?ui)?|swagger-?ui)[a-zA-Z0-9.-]+\.js(\.map)?$',
    r'(?i)(^|/)(lib(64)?/python[23](\.\d{1,2})+/|python/[23](\.\d{1,2})+/lib(64)?/).+$',
    r'(?i)(^|/)[a-z0-9_.]+-[0-9.]+\.dist-info/.+$',
    r'(^|/)vendor/(bundle|ruby)/.*?$',
    r'\.gem$',
)

REGLA_PROPIA = '''[[rules]]
id = "cirdan-fake-token"
description = "Token falso de LowTide (prefijo CIRDAN_FAKE_), de la siembra o de las pruebas"
regex = \'\'\'CIRDAN_FAKE_[A-Za-z0-9_-]{8,}\'\'\'
keywords = ["cirdan_fake_"]
'''

ENCABEZADO = '''\
# Reglas de gitleaks %(version)s para el recolector de GitHub (#16, RC-50, cirdan/recolectores/github.py).
#
# No lo edites a mano: lo genera cirdan/recolectores/gitleaks_reglas.py desde el binario de gitleaks de la imagen, y
# ahí se explica qué cambia respecto de la config por omisión de gitleaks y por qué no se hereda con [extend].
# El recolector siempre pasa este archivo con --config, así que un .gitleaks.toml del repo revisado no se usa, y
# también --ignore-gitleaks-allow, así que un comentario gitleaks:allow en el repo revisado tampoco salta nada.
# Las excepciones del gitleaks de BackKL, si hacen falta, van en un .gitleaks.toml en su raíz, nunca aquí: aquí se
# aplicarían a los repos de los clientes.
#
# Las reglas y la allowlist vienen de la config por omisión de gitleaks %(version)s
# (https://github.com/gitleaks/gitleaks, config/gitleaks.toml), con esta licencia:
#
%(licencia)s
'''


def omision(binario):
    """El texto de la config por omisión que el binario de gitleaks trae embebida con go:embed.

    Go guarda el texto sin terminador, así que su largo sale del encabezado de la variable: un par (puntero, largo) de
    64 bits que apunta poco antes de MARCA. Solo para ELF de 64 bits little endian, como los release linux x64 y arm64.
    Falla si no hay exactamente una marca y un par."""
    with open(binario, 'rb') as f:
        datos = f.read()
    if datos[:6] != b'\x7fELF\x02\x01':
        raise ValueError('gitleaks no es un ELF de 64 bits little endian')
    inicio_ph, = struct.unpack_from('<Q', datos, 0x20)
    tam_ph, num_ph = struct.unpack_from('<HH', datos, 0x36)
    segmentos = []  # (posición en el archivo, dirección, tamaño) de cada segmento PT_LOAD
    for i in range(num_ph):
        tipo, _, posicion, direccion, _, tam = struct.unpack_from('<IIQQQQ', datos, inicio_ph + i * tam_ph)
        if tipo == 1:
            segmentos.append((posicion, direccion, tam))

    def direccion_de(pos):
        for posicion, direccion, tam in segmentos:
            if posicion <= pos < posicion + tam:
                return direccion + pos - posicion
        raise ValueError('posición fuera de los segmentos del ELF')

    def posicion_de(dir_):
        for posicion, direccion, tam in segmentos:
            if direccion <= dir_ < direccion + tam:
                return posicion + dir_ - direccion
        raise ValueError('dirección fuera de los segmentos del ELF')

    marca = datos.find(MARCA.encode())
    if marca == -1 or datos.find(MARCA.encode(), marca + 1) != -1:
        raise ValueError('el binario no trae una sola config embebida')
    bajo, alto = direccion_de(max(marca - 8192, 0)), direccion_de(marca)
    pares = set()
    for pos in range(0, len(datos) - 15, 8):
        puntero, largo = struct.unpack_from('<QQ', datos, pos)
        if bajo <= puntero <= alto and 0 < largo < 4 * 1024 * 1024:
            pares.add((puntero, largo))
    if len(pares) != 1:
        raise ValueError('se esperaba un par (puntero, largo) para la config embebida y hay %d' % len(pares))
    puntero, largo = pares.pop()
    pos = posicion_de(puntero)
    return datos[pos:pos + largo].decode('utf-8')


def version(binario):
    salida = subprocess.run([binario, 'version'], capture_output=True, text=True, check=True, timeout=30).stdout
    if not re.fullmatch(r'\d+\.\d+\.\d+\n?', salida):
        raise ValueError('gitleaks version no dio un número de versión')
    return salida.strip()


def generar(texto, licencia, version):
    """gitleaks_cirdan.toml a partir del texto de la config por omisión, el de la licencia y la versión."""
    titulo = texto.find(MARCA)
    if titulo == -1 or texto.count('\n[allowlist]\n') != 1 or '[extend]' in texto:
        raise ValueError('la config por omisión no tiene la forma esperada')
    cuerpo = texto[titulo:].replace(MARCA, TITULO, 1)
    # La allowlist global es la única tabla [allowlist] sin prefijo: las de cada regla son [rules.allowlist]
    inicio = cuerpo.index('\n[allowlist]\n')
    bloque = re.compile(r"^paths = \[\n((?:    '''.*'''\,\n)+)\]\n", re.M).search(
        cuerpo, inicio, cuerpo.index('\n[[rules]]\n', inicio))
    if not bloque:
        raise ValueError('la allowlist global no trae paths')
    rutas = re.findall(r"^    '''(.*)''',$", bloque.group(1), re.M)
    faltan = [ruta for ruta in CAMBIOS if ruta not in rutas]
    if faltan:
        raise ValueError('estas rutas de CAMBIOS ya no vienen en la config por omisión: %s' % faltan)
    nuevas = [ruta for ruta in rutas if ruta not in CAMBIOS and ruta not in CONSERVADAS]
    if nuevas:
        raise ValueError('la config por omisión trae rutas sin revisar, que van en CAMBIOS o CONSERVADAS: %s' % nuevas)
    nuevas = [CAMBIOS.get(ruta, ruta) for ruta in rutas]
    paths = 'paths = [\n%s]\n' % ''.join("    '''%s''',\n" % ruta for ruta in nuevas if ruta is not None)
    cuerpo = cuerpo[:bloque.start()] + paths + cuerpo[bloque.end():]
    licencia = '\n'.join(('# ' + linea).rstrip() for linea in licencia.strip('\n').split('\n'))
    return ENCABEZADO % {'version': version, 'licencia': licencia} + '\n' + cuerpo.rstrip('\n') + '\n\n' + REGLA_PROPIA


def main():
    binario = shutil.which('gitleaks')
    if not binario:
        sys.exit('gitleaks no está instalado: corre esto dentro de la imagen de la API')
    with open(LICENCIA, encoding='utf-8') as f:
        licencia = f.read()
    sys.stdout.buffer.write(generar(omision(binario), licencia, version(binario)).encode('utf-8'))


if __name__ == '__main__':
    main()

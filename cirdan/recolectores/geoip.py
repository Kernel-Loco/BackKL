"""País, ASN y proveedor de una IP con las bases locales de DB-IP Lite (#15b, RC-166).

No es un recolector (no está en REGISTRO ni tiene MAX_CONSULTAS): es una búsqueda local que usan las fuentes que crean
activos ip (dns y shodan) para enriquecerlos. Nunca consulta la red, así que no gasta cupo ni pide carta.

Bases. DB-IP publica cada mes, normalmente el día 1, IP to ASN Lite e IP to Country Lite en formato MMDB, sin llave ni
cuota, con licencia CC BY 4.0 (atribución en NOTICE):
    https://download.db-ip.com/free/dbip-asn-lite-AAAA-MM.mmdb.gz
    https://download.db-ip.com/free/dbip-country-lite-AAAA-MM.mmdb.gz
No hay URL sin fecha y el 28 oct 2026 solo respondían los dos últimos meses, así que la imagen no las baja al
construirse. Para instalarlas: bajar las dos a mano, descomprimirlas con gzip -d, dejarlas en datos/geo/ (CARPETA,
ignorada por git salvo .gitkeep) y reconstruir la imagen, que copia esa carpeta en /app/datos/geo. Se usan tal como las
publica DB-IP. Si hay varios meses, se toma el más nuevo por nombre (AAAA-MM se ordena bien como texto). Pesan unos
17 MB las dos. City Lite (121 MB) no se usa: el país cubre la ubicación que promete la carta.

Sin base, sin maxminddb o con una base que no abre, lo de esa base (el país, o el ASN y el proveedor) sale
'No disponible' y la fuente agrega un aviso (aviso_sin_base) que nombra solo lo que se perdió, una vez por corrida y
solo si hubo IP que ubicar (ubicable). La fuente no falla por eso. Una base que lanza al leer una IP cuenta como sin
dato. Una IP que no es global (privada, de documentación, multicast) da 'No disponible' sin buscarla, también en
fuente_geo y base_geo: solo se atribuye a DB-IP lo que salió de una base suya.

Al reproducir una grabación, la ubicación sale de la base que esté en ese momento, no de la grabación: por eso cada
activo ip lleva base_geo con el nombre de las bases que se usaron (por ejemplo 'dbip-asn-lite-2026-10').

CDN_POR_ASN: solo ASN que son de un CDN o un proxy inverso y nada más, verificados el 28 oct 2026 en bgp.he.net y
PeeringDB. Un ASN mixto de nube y CDN (Amazon 16509, Microsoft 8075, Google 15169) nunca entra: una IP suya puede ser
un servidor de la empresa. Ahí el CDN sale por el CNAME (shodan.SUFIJOS_CDN), como antes. Tampoco entran CDN77 (60068,
el mismo ASN vende servidores dedicados de DataPacket) ni Edgecast (15133, ahora junto con una nube).

    python -m cirdan.recolectores.geoip 40.65.94.253 2606:4700:4700::1111

Imprime lo que da ubicar más el CDN por ASN, sin descargar nada. Código de salida: 0, o 1 si falta una base.

maxminddb (requirements.txt, en la imagen) se importa solo al abrir una base: la PC de desarrollo puede no tenerlo y
las pruebas corren sin él.
"""
import ipaddress
import json
import re
import sys
import threading
from pathlib import Path

CARPETA = Path(__file__).resolve().parents[2] / 'datos' / 'geo'   # en la imagen, /app/datos/geo
FUENTE_GEO = 'DB-IP Lite'    # atribución: va en los atributos de cada activo ip que sí se buscó en una base
NO_DISPONIBLE = 'No disponible'   # el mismo texto que rdap.NO_DISPONIBLE

# Nombre de cada base sin extensión, como lo publica DB-IP. Un archivo con otro nombre no se toma.
BASE_ASN = re.compile(r'dbip-asn-lite-[0-9]{4}-[0-9]{2}')
BASE_PAIS = re.compile(r'dbip-country-lite-[0-9]{4}-[0-9]{2}')
PAIS_VALIDO = re.compile(r'[A-Z]{2}')                  # ISO 3166 alfa-2
MAX_ASN = 4294967295         # ASN de 32 bits (RFC 6793). El 0 es reservado
MAX_TEXTO = 200              # caracteres del proveedor, como rdap.MAX_TEXTO

# ASN -> CDN o proxy inverso. Los nombres son los de shodan.SUFIJOS_CDN cuando coinciden. Fuentes de cada uno en
# bgp.he.net/AS<n> y peeringdb.com, 28 oct 2026.
CDN_POR_ASN = {13335: 'cloudflare', 54113: 'fastly', 20940: 'akamai', 16625: 'akamai', 19551: 'imperva',
               30148: 'sucuri', 200325: 'bunny', 22822: 'edgio'}

# Ruta -> (lector o None, problema o None). Se abre una vez por proceso y por ruta. El candado es porque el orquestador
# corre escaneos en hilos y dos podrían abrir la misma base a la vez. Reentrante: bases_por_omision lo tiene tomado
# mientras Bases() lo vuelve a pedir.
_LECTORES = {}
_CANDADO = threading.RLock()
_POR_OMISION = []            # las Bases de CARPETA, la primera vez que se piden


class Bases:
    """Las dos bases de una carpeta. .asn y .pais tienen .get(ip), que da un dict o None, o son None si la base no está
    o no abre. .nombres son los archivos que sí abrieron, sin extensión. .problema dice qué faltó, o None."""

    def __init__(self, carpeta=CARPETA):
        self.carpeta = Path(carpeta)
        self.nombres, problemas = [], []
        self.asn = self._lector(BASE_ASN, 'dbip-asn-lite', problemas)
        self.pais = self._lector(BASE_PAIS, 'dbip-country-lite', problemas)
        self.problema = '; '.join(dict.fromkeys(problemas)) or None   # sin repetir 'maxminddb no está instalado'

    def _lector(self, patron, prefijo, problemas):
        rutas = sorted(r for r in self.carpeta.glob(prefijo + '-*.mmdb') if patron.fullmatch(r.stem))
        if not rutas:
            problemas.append('falta %s-AAAA-MM.mmdb en datos/geo' % prefijo)
            return None
        ruta = rutas[-1]     # la más nueva por nombre
        with _CANDADO:
            if ruta not in _LECTORES:
                _LECTORES[ruta] = self._abrir(ruta)
            lector, problema = _LECTORES[ruta]
        if problema:
            problemas.append(problema)
        else:
            self.nombres.append(ruta.stem)
        return lector

    @staticmethod
    def _abrir(ruta):
        """(lector, None) o (None, problema). La única función que usa maxminddb."""
        try:
            import maxminddb
        except ImportError:
            return None, 'maxminddb no está instalado'
        try:
            return maxminddb.open_database(str(ruta)), None
        except Exception as e:  # un archivo dañado o que no es MMDB no detiene la fuente
            return None, 'no se pudo abrir %s (%s)' % (ruta.name, type(e).__name__)


def bases_por_omision():
    """Las Bases de CARPETA, abiertas una sola vez. Una base nueva pide reiniciar el proceso (en la imagen, reconstruir)."""
    with _CANDADO:
        if not _POR_OMISION:
            _POR_OMISION.append(Bases(CARPETA))
        return _POR_OMISION[0]


def ubicable(ip):
    """True si vale la pena buscar la IP: global y no multicast. Un texto que no es IP da False."""
    try:
        d = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return d.is_global and not d.is_multicast


def _leer(lector, ip):
    """El registro de la IP en una base, o {}. Una base que lanza al leer cuenta como sin dato."""
    if lector is None:
        return {}
    try:
        registro = lector.get(ip)
    except Exception:  # nunca lanza por una base rota
        return {}
    return registro if isinstance(registro, dict) else {}


def _pais(registro):
    pais = registro.get('country')
    codigo = pais.get('iso_code') if isinstance(pais, dict) else None
    return codigo if isinstance(codigo, str) and PAIS_VALIDO.fullmatch(codigo) else NO_DISPONIBLE


def _asn(valor):
    # bool es int en Python: True no es el ASN 1.
    if isinstance(valor, int) and not isinstance(valor, bool) and 1 <= valor <= MAX_ASN:
        return valor
    return NO_DISPONIBLE


def _texto(valor):
    """Solo caracteres imprimibles, espacios colapsados y a lo más MAX_TEXTO: el nombre llega al portal y al reporte."""
    if not isinstance(valor, str):
        return NO_DISPONIBLE
    limpio = ' '.join(''.join(c if c.isprintable() else ' ' for c in valor).split())[:MAX_TEXTO].rstrip()
    return limpio or NO_DISPONIBLE


def ubicar(ip, bases=None):
    """País, ASN y proveedor de una IP, con la fuente y las bases usadas. Lo que no se sabe sale 'No disponible'.

    fuente_geo y base_geo solo nombran a DB-IP si la IP sí se buscó en al menos una base que abrió: una IP que no es
    global, o una corrida sin ninguna base, no atribuye a DB-IP datos que DB-IP no dio. Una IP que no es global ni
    siquiera pide las bases, así una corrida con solo IP privadas no abre nada."""
    datos = {'pais': NO_DISPONIBLE, 'asn': NO_DISPONIBLE, 'proveedor': NO_DISPONIBLE, 'fuente_geo': NO_DISPONIBLE,
             'base_geo': NO_DISPONIBLE}
    if not ubicable(ip):
        return datos
    bases = bases_por_omision() if bases is None else bases
    if not bases.nombres:
        return datos
    datos.update(fuente_geo=FUENTE_GEO, base_geo=list(bases.nombres))
    ip = str(ip).strip()
    datos['pais'] = _pais(_leer(bases.pais, ip))
    registro = _leer(bases.asn, ip)
    datos['asn'] = _asn(registro.get('autonomous_system_number'))
    datos['proveedor'] = _texto(registro.get('autonomous_system_organization'))
    return datos


def cdn_por_asn(asn):
    """El CDN o proxy inverso dueño del ASN, o None. Un ASN mixto de nube y CDN da None a propósito."""
    if isinstance(asn, bool) or not isinstance(asn, int):
        return None
    return CDN_POR_ASN.get(asn)


def aviso_sin_base(fuente, bases, sin_asn=None):
    """El aviso de una corrida que no pudo ubicar sus IP, o None si las dos bases abrieron. Nombra solo lo que se
    perdió: con la base de ASN abierta, el ASN y el proveedor sí salen. sin_asn es lo que la fuente agrega cuando falta
    la base de ASN (shodan: que no pudo descartar los CDN por ASN), en el mismo aviso para no repetir el problema."""
    if not bases.problema:
        return None
    sin_pais, sin_base_asn = bases.pais is None, bases.asn is None
    if sin_base_asn and not sin_pais:
        perdido = 'el ASN y el proveedor de las IP quedan'
    elif sin_pais and not sin_base_asn:
        perdido = 'el país de las IP queda'
    else:
        perdido = 'el país, el ASN y el proveedor de las IP quedan'
    aviso = '%s: sin la base local de DB-IP Lite (%s), %s como No disponible' % (fuente, bases.problema, perdido)
    return '%s, y %s' % (aviso, sin_asn) if sin_asn and sin_base_asn else aviso


def _main(argv=None):
    # En Windows, cuando la salida no es la consola (Git Bash, una tubería), Python usa cp1252 y los acentos se rompen.
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print('uso: python -m cirdan.recolectores.geoip <ip> [<ip> ...]', file=sys.stderr)
        return 2
    bases = bases_por_omision()
    aviso = aviso_sin_base('geoip', bases)
    if aviso:
        print(aviso)
    for ip in argv:
        datos = ubicar(ip, bases)
        datos['cdn'] = cdn_por_asn(datos['asn'])
        print(ip, json.dumps(datos, ensure_ascii=False))
    return 1 if aviso else 0


if __name__ == '__main__':
    sys.exit(_main())

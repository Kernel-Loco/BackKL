"""Servicios expuestos y vulnerabilidades conocidas con Shodan InternetDB (#17, RC-49).

InternetDB (https://internetdb.shodan.io/<ip>) da, sin llave, lo que Shodan ya vio de una IP: puertos abiertos,
CPE, tags, nombres y CVE. Nunca se le pide a Shodan que escanee nada y no se toca ningún servidor del dominio. El
contrato (#13) solo pasa el dominio, así que el recolector arma su lista de IP en tres pasos, todos con fuentes que la
carta ya autoriza (Anexo A, actividades 1, 2 y 5):
1. Nombres: los del dominio en los certificados vigentes de Cert Spotter (certspotter.certificados(), sin cambiarlo),
   sin el '*.' de los comodines, más la raíz. Nunca se adivina un nombre. Hasta MAX_NOMBRES con la raíz.
2. IP: un A de cada nombre con 1.1.1.1 y 8.8.8.8, nunca con el DNS del sistema. Sin AAAA: InternetDB es solo IPv4.
3. Servicios: GET a InternetDB por cada IP pública que no sea de un CDN, hasta MAX_IPS, con PAUSA_INTERNETDB entre una
   y otra.
Los nombres que dan otras fuentes no se usan: eso necesita pasar datos entre fuentes (#23).

CDN (politica_uso_etico.md, punto 5: de una IP de CDN solo se registra que existe). Solo se consultan las IPv4 globales
que no son multicast, reservadas ni de 192.88.99.0/24 (consultable). No se consultan las de los rangos IPv4 de
Cloudflare (RANGOS_CLOUDFLARE), las de los rangos IPv4 publicados de CloudFront, Azure Front Door y los bordes propios
de Google (RANGOS_CDN, de rangos_cdn.json, sin red) ni las que llegan por una cadena CNAME en la que cualquier nombre,
intermedio o final, termina en un sufijo de SUFIJOS_CDN (CDN y bordes compartidos conocidos). La cadena sale de la
misma respuesta del A, sin consultas extra (_cadena_cname). Tampoco las de un ASN que es solo de un CDN o un proxy
inverso, aunque no haya CNAME a la vista (geoip.cdn_por_asn con la base local de DB-IP Lite, #15b, RC-166). Un ASN
mixto de nube y CDN (Amazon, Microsoft, Google) no cuenta, porque una IP suya puede ser un servidor de la empresa: ahí
el CDN sale por sus rangos publicados o por el CNAME (RC-49, H11 de la auditoría del 12 nov). Quedan como activo ip
con su marca y sin consulta. Si aun así InternetDB o la API de host traen el tag 'cdn', sus datos se descartan con un
aviso. Una IP
sin ASN conocido, porque falta la base de ASN de DB-IP o porque la base no la trae, no se consulta (RC-49, H11 de la
auditoría del 12 nov): sin el ASN no se puede descartar que sea de un CDN. Queda como activo ip con internetdb
'sin_asn' y la cobertura parcial, así no se cierran sus hallazgos de antes. El aviso de base faltante lo dice
(SIN_CDN_POR_ASN) y, con la base abierta, SIN_ASN cuenta cuántas fueron.

Devuelve:
- un activo ip por IP, con 'hosts' (los nombres que resuelven a ella) e 'internetdb' con puertos, tags, CPE, cuántos
  CVE y los nombres del dominio, o 'sin_datos' con un 404. Solo las IP que InternetDB sí respondió llevan fuente_datos
  'Shodan InternetDB' (atribución). Todas llevan su país, ASN y proveedor de DB-IP Lite (geoip.ubicar), con
  fuente_geo y base_geo, o 'No disponible' sin la base (con un aviso, una vez por corrida y solo si hubo alguna IP
  ubicable). La ubicación no se graba: al reproducir sale de la base del momento,
- un activo service por puerto, '<ip>:<puerto>/<protocolo>', con 'parent' e 'ip_address' = su IP (RC-60 los lee),
- un hallazgo por puerto sobre su activo service, según la familia del puerto:
  - 3389: exposed_rdp (alta).
  - 22, 23, 5900, 5901, 5985 y 5986: exposed_remote_admin (alta).
  - 21, 139, 445, 548, 873 y 2049: exposed_file_sharing (alta).
  - 1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211 y 27017: exposed_database (alta).
  - 2375 y 2376 (Docker), 6443 (Kubernetes), 10250 y 10255 (kubelet) y 2379 y 2380 (etcd): exposed_container_api
    (alta, RC-224), con el servicio que suele escuchar ahí (SERVICIO_CONTENEDORES) y NOTA_CONTENEDORES en la
    evidencia: InternetDB solo da el número del puerto, así que no se sabe si el servicio pide autenticación. Saberlo
    pediría conectarse al servidor, y eso no se hace.
  - 11434 (Ollama), 1234 (LM Studio), 7860 (Gradio), 8188 (ComfyUI), 8265 (Ray Dashboard), 6333 y 6334 (Qdrant) y
    19530 (Milvus): exposed_ai_service (alta, RC-262), con el producto que suele escuchar ahí (SERVICIO_IA) y NOTA_IA
    en la evidencia, por la misma razón. Los puertos genéricos que también usan servicios de IA (3000, 5000, 8000,
    8080 y 8888) siguen en exposed_service, y el 80 y el 443 en el activo web sin hallazgo.
  - 80 y 443, y los de correo (25, 110, 143, 465, 587, 993 y 995): activo service sin hallazgo.
  - los industriales (102, 502, 789, 1911, 2404, 4911, 9600, 20000, 44818 y 47808): exposed_service con
    puerto_industrial en la evidencia. exposed_ot_device sale de la etiqueta 'ics', no del puerto.
  - cualquier otro, como 8080 o 50000: exposed_service (baja).
- known_vulnerability (media) sobre el activo ip, uno por CVE con la CVE como clave, hasta MAX_CVE por IP (las más
  recientes por año y número, y un aviso con cuántas se omitieron). Cada CVE se normaliza a 'CVE-<año>-<número>' sin
  ceros de más antes de quitar repetidas. Son CVE que Shodan deduce de la versión (deducida_por_version), con las CPE
  de esa IP. KEV y EPSS son de #69 (RC-127).
- exposed_ot_device (crítica) con la etiqueta 'ics', exposed_iot_device (alta) con 'iot' y outdated_software (alta) con
  'eol-product' o 'eol-os', sobre el activo ip, uno por código y por IP, con las etiquetas en la evidencia y su parte
  PARTE_ETIQUETAS (RC-220 y RC-337). Las etiquetas salen de InternetDB (fuente_datos 'Shodan InternetDB', sin fecha) o
  de la API de host (fuente_datos 'Shodan', con puerto, producto, versión y fecha de cada servicio).
Las demás etiquetas solo van a los atributos. 'honeypot', de InternetDB o de la API de host, descarta los hallazgos y
servicios de esa IP con un aviso. Los nombres de
InternetDB y de la API de host (hostnames y domains) que no son del dominio no se guardan, solo se cuentan
(hostnames_ajenos). Si una IP los trae, puede ser un dato de quien tuvo la IP antes: la evidencia lleva
posible_dato_de_otro_dueno y queda un aviso. Sin nombres ajenos esa
marca no sale, aunque el dato sea de otro dueño: InternetDB no da fechas ni nombres que lo digan.

Etiquetas y llave (RC-220 y RC-337). Que InternetDB no traiga una etiqueta no prueba que la IP no la tenga: InternetDB no
dice cuándo vio cada puerto ni trae banners. Por eso los códigos de SIN_LLAVE sin hallazgos van a sin_cobertura, salvo
que la API de host de Shodan (GET /shodan/host/<ip>, nunca /shodan/scan ni la búsqueda) haya respondido completa por
todas las IP de una corrida sin otros recortes: entonces cuentan como revisados. La API de host se consulta solo con
SHODAN_API_KEY puesta (crear_cliente la lee), para las mismas IP que van a InternetDB, con PAUSA_INTERNETDB entre una y
otra, y su respuesta se graba limpia (limpiar_host), sin la URL. La llave va en ?key= de la URL y nunca sale en la
grabación, los avisos ni los errores (_tapar). Un 404, un error o el tope de tiempo dejan esa IP sin revisar en sus
etiquetas. Con un hallazgo de etiqueta y otra IP sin revisar, revisados y sin_revisar llevan la parte
'<ip>/etiquetas', así no se cierra lo de una IP que no se pudo revisar. Sin la llave nada de esto corre y la parte de
etiquetas nunca queda revisada. Como InternetDB no da fechas ni dice si un puerto es tcp o udp, lo que sale de InternetDB
lleva en la evidencia vigencia 'sin_fecha', fuente_sin_fecha y nota_vigencia (NOTA_SIN_FECHA: el dato puede ser viejo o de
quien tuvo la IP antes), el protocolo es tcp salvo PUERTOS_UDP, y el activo service lleva protocolo_supuesto.

Cobertura. Si algo quedó sin revisar (Cert Spotter caído o con 429, nombres o IP cortados por MAX_NOMBRES o MAX_IPS, un
A fallido, una IP sin respuesta, una respuesta 200 de InternetDB sin 'ports' o con campos que no se pueden leer, el 429
de InternetDB o el tope de tiempo), los códigos de CODIGOS_PUERTOS sin hallazgos también van a sin_cobertura. Uno con
hallazgos no puede ir ahí (validar() lo rechaza) y solo queda el aviso. Para eso cada puerto lleva su IP como parte y
cada CVE su IP con PARTE_CVE, y revisados lleva las partes que sí quedaron revisadas completas: las de las IP que
InternetDB respondió sin los campos rotos que las deciden (_partes_revisadas), más las privadas y las de un CDN, que
una corrida completa tampoco consulta. Si se conocen todas las IP del dominio (sin páginas, nombres ni A de menos),
sin_revisar lleva las demás partes de esas IP. Así el orquestador no cierra lo de una IP sin respuesta o cortada por
un tope, y sí lo de una IP que ya no es del dominio (#23). Las CVE que MAX_CVE deja fuera van en omitidos con su
huella: siguen ahí y el orquestador no cierra las que se reportaron antes. Si no
queda ninguna IP que consultar y todo respondió, la fuente queda succeeded con 0 hallazgos y un aviso. Si Cert Spotter
y todos los A fallaron, o ninguna IP respondió porque fallaron por la red y el tiempo cortó las demás, si había,
FuenteNoResponde, para que el orquestador la reintente. Una IP cuenta como falla de red si no respondió en sus
intentos, aunque el tiempo no le dejara hacer otro. La que el tiempo cortó antes de su primer intento o mientras se
leía no cuenta como falla de red: si todas quedan así, la fuente queda succeeded y esas IP quedan sin revisar.
Reintentos: 3 intentos por A y por IP (esperas de 5 y 15 s) y 2 por página de Cert Spotter. Un 5xx o un 408 con
Retry-After esperan lo que pide, si es más, hasta MAX_ESPERA aunque pida más, y se reintenta igual. Si después
de la espera no le quedarían a la corrida MIN_INTENTO segundos (más HOLGURA), no se espera ni se hace otro intento: sale
el error del último, que cuenta como el de su A o su IP (esperar). En los A lo que queda ya descuenta RESERVA_INTERNETDB
(restante), así que un A que falla con 115 s por delante ya no espera ni se reintenta. Un solo aviso junta los A
fallidos y dice cuántos se quedaron sin tiempo para otro intento. El
lifetime del A es min(TIMEOUT_DNS, lo que queda). Cada petición HTTP tiene un plazo absoluto, min(TIMEOUT_HTTP o
TIMEOUT_CT, lo que queda), que cubre getaddrinfo, el connect, el TLS, el envío y cada lectura de las cabeceras y del
cuerpo (_descargar con transporte.descargar). Una redirección no se sigue y no se puede leer, y no se usan proxies:
cada consulta llega solo al servidor que se pidió, por https, y cuenta una vez. Solo el 404 de InternetDB es
'sin datos'. Un 200 vacío o 'null' no se puede leer. Un 429 de InternetDB o de Cert Spotter no se reintenta: otro
intento solo gastaría cupo.

Modos: 'vivo' consulta. 'grabar' además guarda lo ya limpio en cirdan/recolectores/respuestas_grabadas/shodan/<dominio>/
(las páginas de Cert Spotter reducidas a lo que lee certspotter.certificado(), cada A con estado, IP y su cadena CNAME,
y cada IP de InternetDB limpia o 'sin_datos' y, con la llave, su respuesta de la API de host limpia o 'sin_datos', sin
la llave ni la URL), todo al final y solo si la corrida no tuvo ninguna falla. Los únicos
recortes que no impiden grabar son los topes deterministas (TOPES: PAGINAS_CT, MAX_NOMBRES y MAX_IPS, más el de MAX_CVE,
que no deja la cobertura parcial), porque otra corrida los repetiría igual. Cualquier falla (un 429, la red, un A sin
respuesta, el tope de tiempo, una respuesta que no se puede leer, un 4xx, una página o una emisión de Cert Spotter rota
o campos rotos de InternetDB) deja intacta la grabación anterior, como github.py con SIN_CUOTA, con el aviso NO_SE_GRABO
al principio de los avisos. Una grabación fallida tampoco la toca. 'reproducir' solo lee esa grabación, sin llave: usa la API de host solo si la grabación trae alguna respuesta suya
(una grabación hecha sin llave reproduce como antes de RC-337). Sin grabación
del dominio, reproducir da los 11 códigos en sin_cobertura y un aviso, no failed, para que la demo no muestre la fuente
caída. dnspython se importa solo al consultar de verdad (_resolver_a), como registros_dns.py.

    python -m cirdan.recolectores.shodan olmardo.com --reproducir
    python -m cirdan.recolectores.shodan olmardo.com --grabar
    python -m cirdan.recolectores.shodan olmardo.com --json

Como github.py, la línea de comandos rechaza vivo y --grabar si el dominio no está en DOMINIOS_EN_VIVO.
Código de salida: 0 si la corrida fue completa (el aviso fijo LIMITES y los códigos de SIN_LLAVE no cuentan), 1 si
queda en 'failed', 2 si la cobertura quedó parcial y 3 si --grabar no escribió por una falla (NO_SE_GRABO): la
grabación anterior sigue igual y hay que repetir --grabar más tarde. Si la falla deja la fuente en failed (por
ejemplo, todas las IP caídas) sale 1, y la grabación anterior también sigue igual.
"""
import argparse
import contextlib
import hashlib
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cirdan.config import config
from cirdan.ml import caracteristicas as rubrica
from cirdan.recolectores import certspotter, contrato, geoip, transporte
from cirdan.recolectores.contrato import CARPETA_GRABADAS as RAIZ_GRABADAS
from cirdan.recolectores.contrato import (NOMBRE_VALIDO, Activo, FuenteNoResponde, Grabadora, Hallazgo, Resultado,
                                          SinGrabacion, con_reintentos, en_alcance_nombre)

FUENTE = 'shodan'
CARPETA_GRABADAS = RAIZ_GRABADAS / 'shodan'

# Código de regla -> severidad base, la del catálogo de reglas (semillas 001 y 004). Los de puertos y CVE salen de los
# puertos y las CVE de InternetDB.
CODIGOS_PUERTOS = {'exposed_rdp': 'high', 'exposed_remote_admin': 'high', 'exposed_file_sharing': 'high',
                   'exposed_database': 'high', 'exposed_container_api': 'high', 'exposed_ai_service': 'high',
                   'exposed_service': 'low',
                   'known_vulnerability': 'medium'}
# Los de etiquetas salen de las etiquetas que Shodan pone a la IP (RC-220 y RC-337).
CODIGOS_ETIQUETA = {'exposed_iot_device': 'high', 'exposed_ot_device': 'critical', 'outdated_software': 'high'}
CODIGOS = dict(CODIGOS_PUERTOS, **CODIGOS_ETIQUETA)
# Etiqueta de Shodan -> código. 'honeypot' no da código: descarta la IP.
ETIQUETAS = {'ics': 'exposed_ot_device', 'iot': 'exposed_iot_device', 'eol-product': 'outdated_software',
             'eol-os': 'outdated_software'}
# Los códigos de etiquetas, que sin una etiqueta no se pueden dar por revisados sin la API de host (con la llave de
# Shodan, #8). Sin hallazgos van a sin_cobertura salvo con la API de host completa en todas las IP. El nombre es de RC-40.
SIN_LLAVE = tuple(CODIGOS_ETIQUETA)

URL_INTERNETDB = 'https://internetdb.shodan.io/'
NOMBRE_INTERNETDB = 'Shodan InternetDB'          # atribución: va en los atributos y la evidencia
URL_HOST = 'https://api.shodan.io/shodan/host/'   # la única ruta de la API de Shodan que se pide, nunca scan ni search
NOMBRE_HOST = 'Shodan'                           # fuente_datos de lo que sale de la API de host
# La forma de una llave de Shodan (32 letras y dígitos), con margen: con otra no se usa ni se manda. Solo caracteres
# que no cambian una URL. El guion bajo deja que las pruebas usen el prefijo CIRDAN_FAKE_ (AGENTS.md regla 7)
LLAVE_VALIDA = re.compile(r'[A-Za-z0-9_]{20,64}')
LLAVE_TAPADA = '***'                             # lo que queda en un texto en lugar de la llave (_tapar)
AGENTE = contrato.AGENTE   # uno solo para todas las fuentes (contrato.py)
ORIGEN = 'cert_spotter_a'                        # de dónde salió la IP: un nombre de Cert Spotter y su A
RESOLVEDORES = ('1.1.1.1', '8.8.8.8')            # públicos y fijos, como registros_dns.py. Nunca el DNS del sistema

PAGINAS_CT = certspotter.COMPARTIDAS  # 2 páginas de Cert Spotter: casi siempre la página y la vacía que cierra
INTENTOS_CT = 2              # intentos por página, como certspotter.COMPLEMENTO
TIMEOUT_CT = 20              # segundos por página
MAX_NOMBRES = 50             # nombres que se resuelven, con la raíz. Con más no se saben todas las IP y la corrida
                             # queda parcial sin sin_revisar (RC-55), así que va más alto que MAX_IPS
MAX_IPS = 10                 # IP que se consultan en InternetDB
MAX_CVE = 25                 # known_vulnerability por IP. Los demás se cuentan en un aviso
INTENTOS = 3                 # intentos por A y por IP dentro de una corrida (no es scan_source_runs.attempt)
ESPERAS = (5, 15)            # segundos entre intentos
TIMEOUT_DNS = 5.0            # tiempo total de un A, con sus dos resolvedores
TIMEOUT_HTTP = 10            # segundos por petición a InternetDB
PAUSA_INTERNETDB = 1         # segundos entre una IP y la siguiente
TIEMPO_CORRIDA = 360         # segundos de toda la corrida, como github.py: ninguna consulta empieza después
MIN_RESTANTE = 5             # con menos segundos que esto ya no se empieza otro nombre ni otra IP
MIN_INTENTO = 1              # segundos que necesita un intento: con menos no se espera ni se intenta
HOLGURA = 0.1                # segundos de más que pide esperar(): time.sleep puede pasarse un poco
MAX_ESPERA = 15              # lo más que se espera un Retry-After, aunque pida más
# Segundos que los A le dejan a InternetDB (RC-55): una petición y una pausa por IP. Sin esto, con MAX_NOMBRES nombres
# unos pocos A que no responden (35 s cada uno con sus intentos) se comen la corrida y no se consulta ninguna IP
RESERVA_INTERNETDB = MAX_IPS * (TIMEOUT_HTTP + PAUSA_INTERNETDB)
# Lo mismo para la API de host, solo con la llave. Con ella, Cert Spotter y los A tienen 140 s de los 360 en vez de 250:
# con varios A que no responden, se cortan más nombres que sin llave (parcial 'tiempo')
RESERVA_HOST = MAX_IPS * (TIMEOUT_HTTP + PAUSA_INTERNETDB)
MAX_BYTES = 1024 * 1024      # tope de una respuesta HTTP
MAX_BYTES_HOST = 8 * 1024 * 1024   # la API de host trae los banners completos, que pueden pasar de 1 MB
MAX_SERVICIOS = 50           # servicios de la API de host que se graban por IP, por puerto
MAX_SERVICIOS_EVIDENCIA = 10   # de esos, los que van en la evidencia de un hallazgo de etiqueta
MAX_TEXTO = 80               # caracteres del producto o la versión de un servicio
# Peor caso de una corrida para el límite diario (#13b): cada intento de cada petición HTTP o DNS, con la API de host.
MAX_CONSULTAS = PAGINAS_CT * INTENTOS_CT + MAX_NOMBRES * INTENTOS + MAX_IPS * INTENTOS + MAX_IPS * INTENTOS

# Puertos por familia. Las listas no se cruzan (pruebas/test_shodan.py lo revisa).
PUERTOS = {
    'exposed_rdp': (3389,),
    'exposed_remote_admin': (22, 23, 5900, 5901, 5985, 5986),
    'exposed_file_sharing': (21, 139, 445, 548, 873, 2049),
    'exposed_database': (1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211, 27017),
    'exposed_container_api': (2375, 2376, 2379, 2380, 6443, 10250, 10255),
    # Servidores de modelos, interfaces y bases de vectores de IA (RC-262). Cada uno es el puerto por omisión de la
    # documentación oficial del producto, revisada el 18 nov 2026:
    'exposed_ai_service': (
        11434,   # Ollama: 'Ollama binds 127.0.0.1 port 11434 by default', https://docs.ollama.com/faq
        1234,    # LM Studio: servidor en http://localhost:1234, https://lmstudio.ai/docs/developer/rest/quickstart
        7860,    # Gradio: GRADIO_SERVER_PORT, por omisión 7860, https://www.gradio.app/guides/environment-variables
        8188,    # ComfyUI: --port, por omisión 8188, https://docs.comfy.org/development/comfyui-server/startup-flags
        8265,    # Ray Dashboard: puerto 8265 del nodo principal,
                 # https://docs.ray.io/en/latest/cluster/configure-manage-dashboard.html
        6333,    # Qdrant: service.http_port, por omisión 6333,
                 # https://qdrant.tech/documentation/ops-configuration/configuration/
        6334,    # Qdrant: service.grpc_port, por omisión 6334,
                 # https://qdrant.tech/documentation/ops-configuration/configuration/
        19530,   # Milvus: proxy.port, por omisión 19530, https://milvus.io/docs/configure_proxy.md
    ),
}
# Qué servicio suele escuchar en cada puerto de exposed_container_api (RC-224). Es lo que suele ser, no lo que es:
# InternetDB solo da el número del puerto.
SERVICIO_CONTENEDORES = {2375: 'Docker', 2376: 'Docker', 2379: 'etcd', 2380: 'etcd', 6443: 'Kubernetes',
                         10250: 'kubelet', 10255: 'kubelet'}
# Lo mismo para exposed_ai_service (RC-262): el producto cuyo puerto por omisión es ese, no el que de verdad escucha.
SERVICIO_IA = {11434: 'Ollama', 1234: 'LM Studio', 7860: 'Gradio', 8188: 'ComfyUI', 8265: 'Ray Dashboard',
               6333: 'Qdrant', 6334: 'Qdrant', 19530: 'Milvus'}
PUERTOS_WEB = (80, 443)
PUERTOS_CORREO = (25, 110, 143, 465, 587, 993, 995)   # exposed_service habla de 'entradas distintas de sitios web y correo'
PUERTOS_INDUSTRIALES = (102, 502, 789, 1911, 2404, 4911, 9600, 20000, 44818, 47808)
PUERTOS_UDP = (123, 161, 500, 1900, 5353, 5683, 47808)  # solo tienen sentido en udp. Los demás se suponen tcp

# Rangos IPv4 publicados de Cloudflare, verificados contra cloudflare.com/ips-v4 el 27 oct 2026. Cambian poco, pero
# cambian: la fecha dice cuándo se revisaron por última vez.
RANGOS_CLOUDFLARE = tuple(ipaddress.ip_network(r) for r in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'))
# Rangos IPv4 publicados de CloudFront ('cloudfront'), Azure Front Door ('azure_front_door') y los bordes propios de
# Google ('google', goog.json menos cloud.json), para las nubes mixtas que geoip.CDN_POR_ASN no lista (RC-49, H11).
# rangos_cdn.py los arma desde los archivos de cada nube, bajados una vez con OK. Se leen sin red y
# RANGOS_CDN_FECHA dice de qué día son: cambian (Azure publica cada semana).
_RANGOS_CDN = json.loads((Path(__file__).resolve().parent / 'rangos_cdn.json').read_text(encoding='utf-8'))
RANGOS_CDN_FECHA = _RANGOS_CDN['procedencia']['descargado']
RANGOS_CDN = tuple((ipaddress.ip_network(r), cdn) for cdn, redes in sorted(_RANGOS_CDN['rangos'].items())
                   for r in redes)
# Sufijo de cualquier nombre de la cadena CNAME, intermedio o final -> CDN o borde compartido. Una IP que llega por una
# cadena con uno de estos no se consulta. Sufijos públicos conocidos, sin verificar en vivo, hasta #15b.
SUFIJOS_CDN = {'cdn.cloudflare.net': 'cloudflare', 'cloudfront.net': 'cloudfront', 'akamaiedge.net': 'akamai',
               'edgekey.net': 'akamai', 'edgesuite.net': 'akamai', 'akamai.net': 'akamai', 'akamaized.net': 'akamai',
               'fastly.net': 'fastly', 'azureedge.net': 'azure_cdn', 'azurefd.net': 'azure_front_door',
               't-msedge.net': 'azure_front_door', 'b-cdn.net': 'bunny', 'incapdns.net': 'imperva',
               'vercel-dns.com': 'vercel', 'netlify.app': 'netlify', 'netlify.com': 'netlify',
               'myshopify.com': 'shopify', 'github.io': 'github_pages', 'herokudns.com': 'heroku'}
# Bordes con un número en el nombre, que no caben en un sufijo fijo: Vercel también da CNAME como
# <hash>.vercel-dns-017.com. Sin verificar en vivo, hasta #15b.
CDN_NUMERADOS = ((re.compile(r'(?:[a-z0-9_-]+\.)*vercel-dns-[0-9]{1,4}\.com'), 'vercel'),)
MAX_SALTOS_CNAME = 16        # nombres de una cadena CNAME que se siguen y se graban
# Lo que nunca se manda a InternetDB aunque ipaddress diga is_global: el relay 6to4 (RFC 7526).
RED_6TO4 = ipaddress.ip_network('192.88.99.0/24')

# Solo dígitos ASCII y a lo más 19 en el número: uno enorme no llega a int() (que desde Python 3.11 lanza ValueError
# con más de 4300 dígitos) y la entrada cuenta como rota.
CVE_VALIDO = re.compile(r'CVE-([0-9]{4})-([0-9]{4,19})')
CPE_VALIDO = re.compile(r'cpe:(?:/|2\.3:)[aho](?::[!-9;-~]*){0,12}')   # CPE 2.2 (cpe:/) y 2.3 (cpe:2.3:), ASCII visible
TAG_VALIDO = re.compile(r'[a-z0-9][a-z0-9_.-]{0,31}')
MAX_CPE = 200                # caracteres de una CPE
ESTADOS_A = ('ok', 'vacio', 'nxdomain')
CAMPOS = ('ports', 'tags', 'cpes', 'vulns', 'hostnames')   # los de una respuesta de InternetDB que se leen

# Avisos con texto fijo.
SIN_GRABACION_DOMINIO = 'shodan: no hay grabación de Shodan de este dominio, no se revisó InternetDB'
_LIMITE_CDN = ('no se detecta un CDN que no llegue por un CNAME conocido, cuyo ASN no esté en '
               'geoip.CDN_POR_ASN y cuya IP no esté en los rangos publicados de CloudFront, Azure Front Door y los bordes '
               'de Google del %s (en las nubes mixtas, por ejemplo Cloud CDN en un balanceador de Google Cloud, que '
               'comparte rangos con las VM, y otros fuera de la lista)' % RANGOS_CDN_FECHA)
LIMITES = ('shodan: solo IPv4 y sin la llave de Shodan (#8): exposed_iot_device, exposed_ot_device y outdated_software '
           'salen solo con las etiquetas de InternetDB y sin ellas quedan sin cobertura, y ' + _LIMITE_CDN)
LIMITES_CON_LLAVE = ('shodan: solo IPv4. exposed_iot_device, exposed_ot_device y outdated_software se revisan con las '
                     'etiquetas de la API de host de Shodan solo en las IP que Shodan conoce, y ' + _LIMITE_CDN)
LLAVE_MAL = 'shodan: SHODAN_API_KEY no tiene la forma de una llave de Shodan, no se usó la API de host'
LLAVE_RECHAZADA = 'shodan: la API de host rechazó la llave (%d), no se consultaron %s'
ETIQUETAS_PARCIAL = ('shodan: la API de host respondió completa por %d de %d IP del dominio: exposed_iot_device, '
                     'exposed_ot_device y outdated_software solo quedan revisados en esas')
PARTE_ETIQUETAS = '/etiquetas'   # las etiquetas de una IP son otra parte que sus puertos y sus CVE
# Lo que shodan agrega al aviso de geoip.aviso_sin_base cuando falta la base de ASN: el filtro de CDN por ASN no corrió.
SIN_CDN_POR_ASN = ('las IP fuera de los rangos de CDN y sin un CNAME de CDN no se consultaron en InternetDB, porque '
                   'sin el ASN no se puede descartar que sean de un CDN')
# Las IP que la base de ASN abierta no trae, por la misma razón.
SIN_ASN = 'shodan: %s sin ASN en la base de DB-IP no se consultaron en InternetDB, porque no se puede descartar un CDN: %s'
SIN_IP = 'shodan: ninguna IP pública del dominio fuera de un CDN, no hubo nada que consultar en InternetDB'
PARCIAL = 'shodan: cobertura parcial'
PARTE_CVE = '/cve'   # las CVE de una IP son otra parte que sus puertos: 'vulns' roto no frena el cierre de sus puertos
NO_SE_GRABO = ('shodan: la corrida tuvo fallas (un 429, la red, el tope de tiempo, una respuesta que no se puede leer o IP '
               'sin ASN), '
               'no se grabó y se conserva la grabación anterior')
NOTA_SIN_FECHA = ('InternetDB no dice cuándo vio este dato: puede ser viejo o de quien tuvo la IP antes que el dominio')
# La de exposed_container_api (RC-224): 'puede permitir', nunca 'permite', porque no se sabe si pide autenticación.
NOTA_CONTENEDORES = ('InternetDB solo dice que el puerto estaba abierto: no dice si el servicio pide autenticación ni '
                     'cuándo lo vio. Si no la pide, puede permitir a cualquiera manejar los contenedores o leer la '
                     'configuración y las claves que guarda.')
# La de exposed_ai_service (RC-262), con la misma regla: InternetDB no dice si pide autenticación ni qué responde.
NOTA_IA = ('InternetDB solo dice que el puerto estaba abierto: no dice si el servicio pide autenticación, qué responde '
           'ni cuándo lo vio. Si no la pide, puede permitir a cualquiera usar los modelos o leer los datos que guarda.')
# Código con servicio probable -> (producto que suele escuchar en cada puerto, nota de autenticación de la evidencia).
PROBABLES = {'exposed_container_api': (SERVICIO_CONTENEDORES, NOTA_CONTENEDORES),
             'exposed_ai_service': (SERVICIO_IA, NOTA_IA)}

TITULOS = {
    'exposed_rdp': 'Shodan vio abierto el escritorio remoto (puerto %d) en %s',
    'exposed_remote_admin': 'Shodan vio abierta una entrada de administración remota (puerto %d) en %s',
    'exposed_file_sharing': 'Shodan vio abierto un servicio para compartir archivos (puerto %d) en %s',
    'exposed_database': 'Shodan vio abierta una base de datos (puerto %d) en %s',
    'exposed_container_api': 'Shodan vio abierto el puerto %d, que suele ser de %s, en %s',
    'exposed_ai_service': 'Shodan vio abierto el puerto %d, que suele ser de %s, en %s',
    'exposed_service': 'Shodan vio abierto el puerto %d en %s',
}
TITULO_CVE = 'Vulnerabilidad conocida %s por la versión que Shodan vio en %s'
TITULOS_ETIQUETA = {
    'exposed_ot_device': 'Shodan marca como equipo de control industrial (%s) a %s',
    'exposed_iot_device': 'Shodan marca como dispositivo conectado (%s) a %s',
    'outdated_software': 'Shodan marca software sin soporte del fabricante (%s) en %s',
}


class LimiteAlcanzado(FuenteNoResponde):
    """La fuente respondió 429: llegó a su límite. No se reintenta en la corrida."""


class SinTiempo(FuenteNoResponde):
    """Se acabó TIEMPO_CORRIDA antes de la consulta."""


class RespuestaIlegible(FuenteNoResponde):
    """La fuente respondió algo que no se puede leer, o un 4xx. Otro intento daría lo mismo."""


class ConsultaFallida(Exception):
    """El DNS no dio respuesta (tiempo agotado, SERVFAIL, ningún servidor contestó): no se sabe la IP."""


FALLAS = {'limite': LimiteAlcanzado, 'tiempo': SinTiempo, 'ilegible': RespuestaIlegible, 'error': FuenteNoResponde}
# Recortes deterministas de la cobertura: otra corrida los repetiría igual, así que no impiden grabar. Cualquier otra
# razón de cobertura parcial es una falla y 'grabar' no escribe (ClienteShodan.degradada).
TOPES = ('paginas', 'nombres', 'ips')
_NO_ENCONTRADO = object()    # el 404, dentro de _http


# ---------------------------------------------------------------- consultas a la red

def _descargar(url, timeout, cronometro=None, tope=MAX_BYTES):
    """El cuerpo de la respuesta, de a lo más `tope` bytes. La única función que hace HTTP.

    `timeout` es el plazo absoluto de toda la petición, de getaddrinfo al último bloque del cuerpo, no solo de cada
    operación de socket (transporte.descargar): si se pasa, lanza SinTiempo. Así un servidor que manda el cuerpo de a
    poco no estira la corrida. Una redirección no se sigue y da RespuestaIlegible. `cronometro` es time.monotonic por
    omisión. Va por certspotter.descargar: una página de Cert Spotter que otra fuente ya pidió en este escaneo no sale a
    la red (RC-326). Las demás URL pasan tal cual."""
    cronometro = cronometro or time.monotonic
    req = urllib.request.Request(url, headers={'User-Agent': AGENTE, 'Accept': 'application/json'})
    try:
        return certspotter.descargar(req, cronometro() + timeout, tope, cronometro)
    except transporte.PlazoVencido:
        raise SinTiempo('shodan: la respuesta tardó más de %s s' % timeout) from None
    except transporte.Redirigida as e:
        raise RespuestaIlegible('shodan: %s' % e) from None


def _cadena_cname(respuesta, nombre):
    """Los nombres de destino de la cadena CNAME de `nombre`, en orden: cada intermedio y el final, sin `nombre`.

    Salen de la sección de respuesta del mensaje que dnspython ya recibió (respuesta.response.answer), así que no hay
    consultas extra, y se completan con respuesta.canonical_name, el último. Sigue a lo más MAX_SALTOS_CNAME nombres y
    se detiene en un ciclo. Solo lee rdtype, name y target, así una prueba la puede llamar con objetos simulados."""
    destinos = {}
    for rrset in getattr(getattr(respuesta, 'response', None), 'answer', None) or ():
        if int(rrset.rdtype) != 5:    # dns.rdatatype.CNAME
            continue
        for rr in rrset:
            destinos[str(rrset.name).lower().rstrip('.')] = str(rr.target).lower().rstrip('.')
    inicio = nombre.lower().rstrip('.')
    cadena, actual = [], inicio
    while actual in destinos and len(cadena) < MAX_SALTOS_CNAME:
        actual = destinos[actual]
        if actual == inicio or actual in cadena:
            break
        cadena.append(actual)
    final = str(respuesta.canonical_name).lower().rstrip('.')
    if final != inicio and final not in cadena and len(cadena) < MAX_SALTOS_CNAME:
        cadena.append(final)
    return cadena


def _resolver_a(nombre, lifetime=TIMEOUT_DNS):
    """La única función que usa dnspython y habla con el resolvedor. Pregunta el A de `nombre` a 1.1.1.1 y 8.8.8.8.

    Devuelve (estado, ips, cadena): ('ok', IP, los nombres de la cadena CNAME, [] sin CNAME), ('vacio', [], []) si el
    nombre existe sin A (NoAnswer) o ('nxdomain', [], []). La cadena sale de la misma respuesta, sin consultas extra
    (_cadena_cname). `lifetime` es el tiempo total del A con sus dos resolvedores. Otra falla de DNS lanza
    ConsultaFallida. dnspython se importa aquí, como en registros_dns.py, porque la PC de desarrollo no lo tiene (está
    en requirements.txt y en la imagen)."""
    import dns.exception
    import dns.resolver
    resolvedor = dns.resolver.Resolver(configure=False)   # nunca el DNS del sistema ni del contenedor
    resolvedor.nameservers = list(RESOLVEDORES)
    resolvedor.lifetime = lifetime
    try:
        respuesta = resolvedor.resolve(nombre, 'A')
    except dns.resolver.NXDOMAIN:
        return 'nxdomain', [], []
    except dns.resolver.NoAnswer:
        return 'vacio', [], []
    except dns.exception.DNSException as e:
        raise ConsultaFallida('%s: %s' % (type(e).__name__, e)) from None
    return 'ok', [r.address for r in respuesta], _cadena_cname(respuesta, nombre)


# ---------------------------------------------------------------- limpieza de lo que se graba

def _entero(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _nombre(x):
    """Un nombre en minúsculas y sin punto final, o None si no es válido."""
    if not isinstance(x, str):
        return None
    x = x.strip().lower().rstrip('.')
    return x if NOMBRE_VALIDO.fullmatch(x) else None


def _ipv4(x):
    try:
        return isinstance(x, str) and ipaddress.ip_address(x.strip()).version == 4
    except ValueError:
        return False


def limpiar_a(estado, ips, cnames):
    """{estado, ips, cnames} de un A, como se graba: solo IPv4 válidas, ordenadas y sin repetir, y los nombres válidos
    de la cadena CNAME en su orden, sin repetir y hasta MAX_SALTOS_CNAME. `cnames` puede ser una lista, un solo nombre
    o None. ValueError si no tiene esa forma (una grabación rota, o un resolvedor que devuelve otra cosa)."""
    if estado not in ESTADOS_A or not isinstance(ips, (list, tuple)):
        raise ValueError('forma inesperada')
    if cnames is None or isinstance(cnames, str):
        cnames = [cnames] if cnames else []
    if not isinstance(cnames, (list, tuple)):
        raise ValueError('forma inesperada')
    limpias = sorted({ipaddress.ip_address(ip.strip()) for ip in ips if _ipv4(ip)})
    cadena = []
    for c in map(_nombre, cnames):
        if c and c not in cadena:
            cadena.append(c)
    return {'estado': estado, 'ips': [str(ip) for ip in limpias] if estado == 'ok' else [],
            'cnames': cadena[:MAX_SALTOS_CNAME] if estado == 'ok' else []}


def reducir_pagina(pagina):
    """Una página de Cert Spotter con solo lo que lee certspotter.certificado(): sin huellas ni llaves públicas."""
    reducida = []
    for e in pagina:
        if not isinstance(e, dict):
            continue
        emisor = e.get('issuer')
        emisor = emisor.get('name') or emisor.get('friendly_name') if isinstance(emisor, dict) else emisor
        reducida.append({'id': e.get('id'), 'dns_names': e.get('dns_names'), 'not_before': e.get('not_before'),
                         'not_after': e.get('not_after'), 'revoked': e.get('revoked') is True,
                         'issuer': {'name': emisor if isinstance(emisor, str) else ''}})
    return reducida


def _cve(v):
    """'CVE-<año>-<número>' con el número sin ceros de más (mínimo 4 dígitos), o None si no es una CVE válida.
    Así 'cve-2014-00160' y 'CVE-2014-0160' son la misma."""
    m = CVE_VALIDO.fullmatch(v.strip().upper()) if isinstance(v, str) else None
    return 'CVE-%s-%04d' % (m.group(1), int(m.group(2))) if m else None


def limpiar_internetdb(datos, dominio):
    """Lo que se usa y se graba de una respuesta de InternetDB, o None si no es un objeto.

    {'cdn': True} si trae el tag 'cdn': de esa IP no se guarda nada más. {'sin_datos': True} es el 404. Si no,
    {ports, tags, cpes, vulns, hostnames, hostnames_ajenos, rotos}: solo puertos de 1 a 65535, tags, CPE (2.2 o 2.3) y
    CVE con forma válida (normalizadas con _cve, de la más reciente a la más vieja), y solo los nombres del dominio. Los
    demás nombres solo se cuentan. 'rotos' lista los campos que traían algo que no se pudo leer y se ignoró, y 'ports'
    si la respuesta no lo traía. Lee igual la respuesta de InternetDB y lo que ya grabó, así una
    grabación cambiada a mano no mete otra cosa."""
    if not isinstance(datos, dict):
        return None
    if datos.get('sin_datos') is True:
        return {'sin_datos': True}
    rotos = {c for c in (datos.get('rotos') or ()) if c in CAMPOS} if isinstance(datos.get('rotos'), list) else set()

    def lista(campo):
        valor = datos.get(campo, [])
        if not isinstance(valor, list):
            rotos.add(campo)
            return []
        return valor

    tags = sorted({t for t in lista('tags') if isinstance(t, str) and TAG_VALIDO.fullmatch(t)})
    if len(tags) != len(set(map(str, lista('tags')))):
        rotos.add('tags')
    if datos.get('cdn') is True or 'cdn' in tags:
        return {'cdn': True}
    puertos = sorted({p for p in lista('ports') if _entero(p) and 1 <= p <= 65535})
    if len(puertos) != len({p if _entero(p) else repr(p) for p in lista('ports')}):
        rotos.add('ports')
    cpes = sorted({c for c in lista('cpes') if isinstance(c, str) and len(c) <= MAX_CPE and CPE_VALIDO.fullmatch(c)})
    if len(cpes) != len(set(map(repr, lista('cpes')))):
        rotos.add('cpes')
    if 'ports' not in datos:   # un 200 sin 'ports' no dice qué puertos vio: no es 'ninguno'
        rotos.add('ports')
    cves = [_cve(v) for v in lista('vulns')]
    vulns = sorted(set(filter(None, cves)), key=lambda v: tuple(int(n) for n in v.split('-')[1:]), reverse=True)
    if None in cves:
        rotos.add('vulns')
    del_dominio, ajenos = set(), 0
    for h in lista('hostnames'):
        nombre = _nombre(h)
        if nombre and en_alcance_nombre(nombre, dominio):
            del_dominio.add(nombre)
        else:
            ajenos += 1
    previos = datos.get('hostnames_ajenos', 0)
    ajenos += previos if _entero(previos) and previos > 0 else 0
    return {'ports': puertos, 'tags': tags, 'cpes': cpes, 'vulns': vulns, 'hostnames': sorted(del_dominio),
            'hostnames_ajenos': ajenos, 'rotos': sorted(rotos)}


def _texto(x):
    """El producto o la versión de un servicio: texto imprimible de una línea, de a lo más MAX_TEXTO caracteres, o None
    si no viene. ValueError si no es texto."""
    if x is None:
        return None
    if not isinstance(x, str):
        raise ValueError('forma inesperada')
    x = ''.join(c for c in ' '.join(x.split()) if c.isprintable())
    return x[:MAX_TEXTO] or None


def _visto(x):
    """La fecha de un servicio de la API de host ('2026-11-10T12:34:56.123456', UTC) como '2026-11-10T12:34:56Z'.
    ValueError si no es una fecha."""
    if not isinstance(x, str) or len(x) > 40:
        raise ValueError('forma inesperada')
    d = datetime.fromisoformat(x.strip())
    d = d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
    return d.strftime('%Y-%m-%dT%H:%M:%SZ')


def _servicio(b, grabado):
    """Un servicio limpio, {puerto, protocolo, producto, version, visto, tags}, de un banner de la API de host (`grabado`
    False: port, transport, product, version, timestamp y tags) o de lo ya grabado. ValueError si algo no se puede
    leer. Nunca guarda el banner, el HTML, los certificados ni los nombres: solo esos seis campos."""
    if not isinstance(b, dict):
        raise ValueError('forma inesperada')
    claves = (('puerto', 'protocolo', 'producto', 'version', 'visto', 'tags') if grabado else
              ('port', 'transport', 'product', 'version', 'timestamp', 'tags'))
    puerto, protocolo_, producto, version, visto, tags = (b.get(k) for k in claves)
    if not (_entero(puerto) and 1 <= puerto <= 65535) or protocolo_ not in ('tcp', 'udp'):
        raise ValueError('forma inesperada')
    tags = [] if tags is None else tags
    if not isinstance(tags, list) or not all(isinstance(t, str) and TAG_VALIDO.fullmatch(t) for t in tags):
        raise ValueError('forma inesperada')
    return {'puerto': puerto, 'protocolo': protocolo_, 'producto': _texto(producto), 'version': _texto(version),
            'visto': _visto(visto), 'tags': sorted(set(tags))}


def limpiar_host(datos, dominio):
    """Lo que se usa y se graba de una respuesta de la API de host, o None si no es un objeto.

    {'sin_datos': True} es el 404 y {'cdn': True} el tag 'cdn': como en InternetDB, de esa IP no se guarda nada más
    (docs/politica_uso_etico.md, sección 2, punto 5). Si no, {tags, servicios, hostnames_ajenos, rotos}: las
    etiquetas de la IP, cuántos nombres de hostnames y domains no son de `dominio` y, por puerto y protocolo, el
    servicio visto más reciente (_servicio), hasta MAX_SERVICIOS. 'rotos' lista 'tags' si no viene o trae algo que no
    se puede leer y 'data' si los servicios no vienen o uno no se puede leer: esa IP no queda revisada en sus
    etiquetas. Lee igual la respuesta de Shodan y lo que ya grabó. Nada más de la respuesta se guarda: ni nombres,
    ni banners, ni ubicación, ni CVE (las da InternetDB)."""
    if not isinstance(datos, dict):
        return None
    if datos.get('sin_datos') is True:
        return {'sin_datos': True}
    if datos.get('cdn') is True or (isinstance(datos.get('tags'), list) and 'cdn' in datos['tags']):
        return {'cdn': True}
    grabado = 'servicios' in datos
    rotos = ({c for c in datos.get('rotos') if c in ('tags', 'data')} if grabado and isinstance(datos.get('rotos'), list)
             else set())
    crudas = datos.get('tags')
    if not isinstance(crudas, list):   # un 200 sin 'tags' no dice que no tenga ninguna
        rotos.add('tags')
        crudas = []
    tags = sorted({t for t in crudas if isinstance(t, str) and TAG_VALIDO.fullmatch(t)})
    if len(tags) != len({t if isinstance(t, str) else repr(t) for t in crudas}):
        rotos.add('tags')
    banners = datos.get('servicios' if grabado else 'data')
    if not isinstance(banners, list):
        rotos.add('data')
        banners = []
    por_puerto = {}
    for b in banners:
        try:
            s = _servicio(b, grabado)
        except (ValueError, TypeError, OverflowError):
            rotos.add('data')
            continue
        clave = (s['puerto'], s['protocolo'])
        if clave not in por_puerto or s['visto'] > por_puerto[clave]['visto']:
            por_puerto[clave] = s
    servicios = [por_puerto[k] for k in sorted(por_puerto)][:MAX_SERVICIOS]
    # Los nombres que no son del dominio solo se cuentan, como en limpiar_internetdb: pueden ser de quien tuvo la IP
    nombres = [_nombre(n) for campo in ('hostnames', 'domains') if isinstance(datos.get(campo), list)
               for n in datos[campo]]
    ajenos = len({n for n in nombres if n and not en_alcance_nombre(n, dominio)}) + sum(1 for n in nombres if not n)
    previos = datos.get('hostnames_ajenos', 0)
    ajenos += previos if _entero(previos) and previos > 0 else 0
    return {'tags': tags, 'servicios': servicios, 'hostnames_ajenos': ajenos, 'rotos': sorted(rotos)}


def _tapar(texto, llave):
    """`texto` sin la llave: ni la llave misma ni lo que siga a un 'key=' (una URL de la API de host en un error)."""
    texto = str(texto)
    if llave:
        texto = texto.replace(llave, LLAVE_TAPADA)
    return re.sub(r'(?i)key=[^&\s\'"]*', 'key=' + LLAVE_TAPADA, texto)


def _tapada(error, llave):
    """Otro error de la misma clase que `error`, con su texto sin la llave y sus marcas (sin_tiempo y codigo)."""
    nuevo = type(error)(_tapar(error, llave))
    for marca in ('sin_tiempo', 'codigo'):
        if hasattr(error, marca):
            setattr(nuevo, marca, getattr(error, marca))
    return nuevo


def _llave_de_config():
    """SHODAN_API_KEY del entorno o del .env, o '' sin ella. Solo la lee crear_cliente."""
    return (config('SHODAN_API_KEY', '') or '').strip()


# ---------------------------------------------------------------- cliente, grabación y reproducción

class ClienteShodan:
    """Hace las consultas (Cert Spotter, el A y InternetDB) con reintentos y, según el modo, graba o reproduce lo ya
    limpio con la Grabadora del contrato (#13).

    `descargar(url, timeout)` y `resolver(nombre, lifetime)` hacen la consulta. Si no se pasan, se usan _descargar y
    _resolver_a, buscados en el módulo en cada consulta, así una prueba los puede cambiar con mock.patch.object.
    `cronometro` y `dormir` son time.monotonic y time.sleep por omisión. `consultas` suma cada intento de cada petición HTTP o DNS.
    `llave` es la de la API de host de Shodan: sin ella ('', por omisión) no se consulta. Solo crear_cliente la pasa,
    desde SHODAN_API_KEY. Al reproducir no se usa."""

    PREFIJO = 'shodan: '             # lo que abre sus errores. La visita web (visita.py) hereda el cliente con el suyo
    TIEMPO_CORRIDA = TIEMPO_CORRIDA
    TOPES = TOPES

    def __init__(self, modo='vivo', carpeta=CARPETA_GRABADAS, descargar=None, resolver=None, nueva=False, reloj=None,
                 cronometro=None, dormir=None, llave=''):
        self.modo = modo
        self.llave = '' if modo == 'reproducir' else (llave or '')
        self.grabadora = Grabadora(carpeta, modo, nueva=nueva, reloj=reloj, sobre=True)
        self.descargar, self.resolver = descargar, resolver
        self.cronometro = cronometro or time.monotonic
        self.dormir = dormir or time.sleep
        self.consultas = 0
        self.inicio = None
        self.reserva = 0       # segundos de la corrida que restante() no cuenta (RESERVA_INTERNETDB mientras van los A)
        self.pendientes = []   # lo que se graba cuando la corrida termina
        self.fallas = 0        # consultas que fallaron en esta corrida, de cualquier tipo
        self.raras_ct = 0      # emisiones de Cert Spotter que no se pueden leer (certspotter.legible)

    @property
    def leidas(self):
        """(archivo, fecha de grabación) de cada respuesta tomada del disco."""
        return self.grabadora.leidas

    def hay_grabacion(self):
        return any(Path(self.grabadora.carpeta).glob('*.json'))

    def usa_host(self):
        """(True si la corrida consulta la API de host, aviso o None). En vivo y al grabar, con una llave con forma de
        llave de Shodan (con otra forma, el aviso LLAVE_MAL, sin su valor). Al reproducir, si la grabación trae alguna
        respuesta de la API de host."""
        if self.modo == 'reproducir':
            return any(Path(self.grabadora.carpeta).glob('host_*.json')), None   # contrato.nombre_archivo('host:<ip>')
        if not self.llave:
            return False, None
        if not LLAVE_VALIDA.fullmatch(self.llave):
            return False, LLAVE_MAL
        return True, None

    def empezar(self):
        self.inicio = self.cronometro()

    def restante(self):
        """Segundos que le quedan a la corrida, sin la reserva. Al reproducir no hay consultas y no hay tope."""
        if self.modo == 'reproducir':
            return self.TIEMPO_CORRIDA
        if self.inicio is None:
            self.inicio = self.cronometro()
        return self.TIEMPO_CORRIDA - self.reserva - (self.cronometro() - self.inicio)

    def esperar(self, segundos):
        """El dormir de con_reintentos. Si después de esperar `segundos` quedaría menos de MIN_INTENTO más HOLGURA para
        otro intento, no espera y devuelve False: con_reintentos sale con el error del último intento, que es el que
        vale, sin un intento más que no alcanzaría a terminar. Después de dormir lo vuelve a revisar, por si el sueño se
        pasó: así el intento no empieza sin tiempo y su SinTiempo no tapa el error."""
        if self.restante() - segundos < MIN_INTENTO + HOLGURA:
            return False
        self.dormir(segundos)
        return self.restante() >= MIN_INTENTO + HOLGURA

    def degradada(self, parcial=()):
        """True si la corrida tuvo alguna falla: una consulta que falló, de cualquier tipo, o una razón de cobertura
        parcial (`parcial`, de _revisar) que no es un tope determinista de TOPES. Con eso 'grabar' no escribe."""
        return bool(self.fallas) or bool(set(parcial) - set(self.TOPES))

    def terminar(self):
        """La corrida terminó: graba todo lo pendiente. Una corrida que falla no llega aquí y no toca la grabación."""
        for consulta, datos in self.pendientes:
            self.grabadora.guardar(consulta, datos)
        self.pendientes = []

    def _grabar(self, consulta, datos):
        if self.modo == 'grabar':
            self.pendientes.append((consulta, datos))

    def _de_disco(self, consulta):
        """(True, datos) si sale de la grabación. Una corrida con fallas ya no se graba, pero una grabación de antes o
        editada a mano puede traer una falla: se lanza otra vez, con su clase y su texto, y no se lee como datos. Un
        archivo vacío, truncado, que no es JSON o sin su sobre {grabado, datos} es una consulta que no llegó
        (FuenteNoResponde), nunca un error que tumbe la fuente ni una respuesta sin datos: vale para toda consulta,
        también el A y las páginas de Cert Spotter."""
        try:
            del_disco, datos = self.grabadora.de_disco(consulta)
        except (ValueError, KeyError, TypeError, AttributeError):   # SinGrabacion no es ninguna de estas
            raise FuenteNoResponde(self.PREFIJO + 'la grabación de %s no se puede leer' % consulta) from None
        if del_disco and isinstance(datos, dict) and 'falla' in datos:
            raise FALLAS.get(datos.get('tipo'), FuenteNoResponde)(str(datos['falla'])[:300])
        return del_disco, datos

    def _consultar(self, consulta, funcion):
        """Corre `funcion` y cuenta su falla (no la de la grabación) en `fallas`: con una, 'grabar' no escribe."""
        try:
            return funcion()
        except SinGrabacion:
            raise
        except FuenteNoResponde:
            self.fallas += 1
            raise

    def _transporte(self, url, timeout):
        """La petición HTTP por omisión: _descargar, buscada en el módulo en cada consulta (mock.patch.object). La
        visita web la cambia por la suya, con otro tope de bytes."""
        return _descargar(url, timeout)

    def _transporte_host(self, url, timeout, que='la API de host'):
        """La petición HTTP de la API de host: _descargar con MAX_BYTES_HOST. El ValueError de transporte.descargar (una
        respuesta de más de MAX_BYTES_HOST, de otro tipo de contenido o sin https) daría lo mismo otra vez: es
        RespuestaIlegible, que no se reintenta. Sin el texto del ValueError, que puede traer la URL con la llave. `que`
        nombra la IP, como en los demás avisos de host()."""
        error = None
        try:
            return _descargar(url, timeout, tope=MAX_BYTES_HOST)
        except ValueError as e:
            error = RespuestaIlegible(self.PREFIJO + '%s dio una respuesta que no se puede leer (%s: más de %d bytes, '
                                      'otro tipo de contenido o sin https)' % (que, type(e).__name__, MAX_BYTES_HOST))
        raise error

    def _http(self, url, intentos, timeout, que, sin_reintento=(), turno=None, peticion=None, contar=True):
        """JSON de `url` con hasta `intentos` intentos dentro del tiempo de la corrida. None solo con un 404. Un 429
        lanza LimiteAlcanzado, y otro 4xx, un 200 vacío o 'null' o una redirección RespuestaIlegible, sin reintentar.
        Si un 5xx o un 408 traen Retry-After, el siguiente intento espera lo que piden si es más que ESPERAS y le
        alcanza a la corrida, pero nunca más de MAX_ESPERA. `turno()`, si se pasa, corre antes de cada intento, también
        de los reintentos: la visita web espera ahí el ritmo de la NVD. `peticion` cambia la petición por omisión
        (_transporte), salvo que el cliente traiga `descargar`. Un RespuestaIlegible por un 4xx lleva el código en
        `codigo`. Con `contar` en False los intentos no suman a `consultas`: lo que repite certspotter.descargar."""
        pedida = {}   # el Retry-After del último intento

        def intento():
            pedida.clear()
            if turno:
                turno()
            limite = min(timeout, self.restante())
            if limite < MIN_INTENTO:
                raise SinTiempo(self.PREFIJO + 'se acabó el tiempo de la corrida antes de consultar %s' % que)
            self.consultas += 1 if contar else 0
            try:
                cuerpo = (self.descargar or peticion or self._transporte)(url, limite)
            except SinTiempo:
                # La respuesta se pasó de su plazo. Si con eso se acabó la corrida, es el corte por tiempo. Si no, es
                # una respuesta lenta y cuenta como una falla de red, que con_reintentos reintenta.
                if self.restante() < MIN_INTENTO:
                    raise SinTiempo(self.PREFIJO + 'se acabó el tiempo de la corrida mientras se leía %s' % que) from None
                raise TimeoutError(self.PREFIJO + '%s tardó más de %s s en responder' % (que, limite)) from None
            except urllib.error.HTTPError as e:
                codigo, espera = e.code, (e.headers or {}).get('Retry-After')
                pedida['segundos'] = min(transporte.retry_after(e.headers) or 0, MAX_ESPERA)   # aunque pida más
                with contextlib.suppress(Exception):
                    e.close()
                if codigo == 404:
                    return _NO_ENCONTRADO
                if codigo == 429:
                    raise LimiteAlcanzado(self.PREFIJO + '%s llegó a su límite de consultas (429, Retry-After %s s)'
                                          % (que, espera or '?')) from None
                if codigo in sin_reintento or (codigo < 500 and codigo != 408):
                    ilegible = RespuestaIlegible(self.PREFIJO + '%s respondió %d' % (que, codigo))
                    ilegible.codigo = codigo
                    raise ilegible from None
                raise
            if not cuerpo or not cuerpo.strip():
                raise RespuestaIlegible(self.PREFIJO + '%s respondió sin cuerpo' % que)
            try:
                datos = transporte.json_de(cuerpo)
            except transporte.JsonProfundo:  # más de transporte.MAX_NIVELES_JSON niveles (RC-300)
                raise RespuestaIlegible(self.PREFIJO + '%s respondió JSON que no se puede leer' % que) from None
            if datos is None:
                raise RespuestaIlegible(self.PREFIJO + '%s respondió null' % que)
            return datos
        intento.__name__ = self.PREFIJO + '%s no respondió' % que
        datos = con_reintentos(intento, intentos=intentos, esperas=ESPERAS,
                               dormir=lambda segundos: self.esperar(max(segundos, pedida.get('segundos') or 0)))
        return None if datos is _NO_ENCONTRADO else datos

    def pedir(self, consulta, url, fuente=certspotter.NOMBRE, intentos=INTENTOS_CT, timeout=None, pausa=0,
              sin_reintento=(), texto=None, valida=None):
        """La lista JSON de `url`, con la misma firma de ClienteCrtsh.pedir, así certspotter.certificados() la usa sin
        cambios. Se graba la página reducida (reducir_pagina). Una respuesta que no es lista, o con la que `valida`
        da False, cuenta como una que no llegó y no se reintenta. Una página que otra fuente ya pidió en este escaneo
        (certspotter.repetida, RC-326) se lee de lo que ella recibió, en un solo intento, sin pausa y sin contarla en
        `consultas`."""
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            if not isinstance(datos, list):
                raise FuenteNoResponde(self.PREFIJO + 'la grabación de %s no se puede leer' % consulta)
        else:
            que = '%s (%s)' % (fuente, texto or consulta)
            repetida = certspotter.repetida(url)

            def pagina():
                if pausa and not repetida:
                    self.dormir(pausa)
                datos = self._http(url, 1 if repetida else intentos, timeout or TIMEOUT_CT, que, sin_reintento,
                                   contar=not repetida)
                if not isinstance(datos, list) or (valida and not valida(datos)):
                    raise RespuestaIlegible(self.PREFIJO + '%s respondió algo que no se puede leer' % que)
                return reducir_pagina(datos)
            datos = self._consultar(consulta, pagina)
            self._grabar(consulta, datos)
        # Una emisión que certificados() salta deja la lista incompleta: es una falla, no el tope de páginas
        self.raras_ct += sum(1 for e in datos if not certspotter.legible(e))
        return datos

    def resolver_a(self, nombre):
        """{estado, ips, cnames} del A de `nombre`. Lanza FuenteNoResponde si el DNS no respondió en INTENTOS intentos.
        El lifetime de cada intento es min(TIMEOUT_DNS, lo que le queda a la corrida)."""
        consulta = 'a:' + nombre
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            try:
                return limpiar_a(datos['estado'], datos['ips'], datos.get('cnames', datos.get('cname')))
            except (ValueError, KeyError, TypeError, AttributeError):
                raise FuenteNoResponde(self.PREFIJO + 'la grabación de %s no se puede leer' % consulta) from None

        def intento():
            limite = min(TIMEOUT_DNS, self.restante())
            if limite < MIN_INTENTO:
                raise SinTiempo(self.PREFIJO + 'se acabó el tiempo de la corrida antes de resolver %s' % nombre)
            self.consultas += 1
            return limpiar_a(*(self.resolver or _resolver_a)(nombre, limite))
        intento.__name__ = self.PREFIJO + 'el DNS no respondió al A de %s' % nombre

        datos = self._consultar(consulta, lambda: con_reintentos(intento, intentos=INTENTOS, esperas=ESPERAS,
                                                                 errores=(ConsultaFallida,), dormir=self.esperar))
        self._grabar(consulta, datos)
        return datos

    def internetdb(self, ip, dominio, pausa=0):
        """Lo que InternetDB sabe de `ip`, ya limpio (limpiar_internetdb). Un 404 es {'sin_datos': True}. Una respuesta
        que no es un objeto lanza RespuestaIlegible, sin reintento."""
        consulta = 'internetdb:' + ip
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            limpio = limpiar_internetdb(datos, dominio)
            if limpio is None:
                raise FuenteNoResponde(self.PREFIJO + 'la grabación de %s no se puede leer' % consulta)
            return limpio
        que = 'InternetDB (%s)' % ip

        def consulta_ip():
            if pausa:
                self.dormir(pausa)
            crudo = self._http(URL_INTERNETDB + ip, INTENTOS, TIMEOUT_HTTP, que)
            limpio = {'sin_datos': True} if crudo is None else limpiar_internetdb(crudo, dominio)
            if limpio is None:
                raise RespuestaIlegible(self.PREFIJO + '%s respondió algo que no es un objeto' % que)
            return limpio
        limpio = self._consultar(consulta, consulta_ip)
        self._grabar(consulta, limpio)
        return limpio

    def host(self, ip, dominio, pausa=0):
        """Lo que la API de host de Shodan sabe de `ip`, ya limpio (limpiar_host). Un 404 es {'sin_datos': True}.

        La llave solo va en la URL que se manda. Todo error que sale de aquí es de las clases de FuenteNoResponde y
        lleva su texto sin la llave (_tapada); uno inesperado sale como RespuestaIlegible con solo su clase, así su
        texto, que puede traer la URL, no llega a los avisos ni a scan_source_runs.error."""
        consulta = 'host:' + ip   # el nombre de la grabación, sin la llave
        del_disco, datos = self._de_disco(consulta)
        if del_disco:
            limpio = limpiar_host(datos, dominio)
            if limpio is None:
                raise FuenteNoResponde(self.PREFIJO + 'la grabación de %s no se puede leer' % consulta)
            return limpio
        llave = self.llave
        que = 'la API de host (%s)' % ip

        def consulta_ip():
            if pausa:
                self.dormir(pausa)
            crudo = self._http(URL_HOST + ip + '?key=' + llave, INTENTOS, TIMEOUT_HTTP, que,
                               peticion=lambda url, timeout: self._transporte_host(url, timeout, que))
            limpio = {'sin_datos': True} if crudo is None else limpiar_host(crudo, dominio)
            if limpio is None:
                raise RespuestaIlegible(self.PREFIJO + '%s respondió algo que no es un objeto' % que)
            return limpio
        # El error tapado se lanza fuera del except: dentro, su __context__ guardaría el original, y detrás de él el
        # HTTPError o el KeyError con la URL y la llave (como keyvault._con_reintentos)
        tapada = None
        try:
            limpio = self._consultar(consulta, consulta_ip)
        except FuenteNoResponde as e:
            tapada = _tapada(e, llave)
        except Exception as e:   # noqa: BLE001 - nunca el texto: puede traer la URL con la llave
            self.fallas += 1
            tapada = RespuestaIlegible(self.PREFIJO + '%s falló (%s)' % (que, type(e).__name__))
        if tapada is not None:
            raise tapada
        if limpio.get('rotos'):
            # Una respuesta que no se puede leer entera es una falla, como los campos rotos de InternetDB: 'grabar'
            # no pisa la grabación anterior
            self.fallas += 1
        self._grabar(consulta, limpio)
        return limpio


def carpeta_de(dominio):
    """Carpeta de la grabación de un dominio."""
    return CARPETA_GRABADAS / dominio.strip().lower().rstrip('.')


def crear_cliente(modo, dominio):
    """Cliente para el orquestador (#13): 'vivo' consulta, 'reproducir' usa la grabación del dominio y 'grabar' empieza
    una grabación nueva. En vivo y al grabar lleva la llave de SHODAN_API_KEY, si está puesta (RC-337)."""
    return ClienteShodan(modo=modo, carpeta=carpeta_de(dominio), nueva=(modo == 'grabar'),
                         llave='' if modo == 'reproducir' else _llave_de_config())


def _en_vivo_permitido(dominio):
    """Lo mismo que orquestador.en_vivo_permitido(), sin importar el orquestador (que importa los recolectores)."""
    permitidos = {d.strip().lower() for d in config('DOMINIOS_EN_VIVO', 'olmardo.com').split(',') if d.strip()}
    return '*' in permitidos or dominio in permitidos


# ---------------------------------------------------------------- reglas

def codigo_de_puerto(puerto):
    """El código de un puerto, o None para los de sitios web y correo, que dan servicio sin hallazgo."""
    for codigo, puertos in PUERTOS.items():
        if puerto in puertos:
            return codigo
    if puerto in PUERTOS_WEB or puerto in PUERTOS_CORREO:
        return None
    return 'exposed_service'


def protocolo(puerto):
    return 'udp' if puerto in PUERTOS_UDP else 'tcp'


def consultable(ip):
    """True si la IP se puede mandar a InternetDB: IPv4 global, no multicast, no reservada y fuera de 192.88.99.0/24.
    ipaddress da is_global True para multicast (224.0.0.0/4, con 233.252.0.0/24 de documentación) y para el relay
    6to4, así que no basta."""
    d = ipaddress.ip_address(ip)
    return d.version == 4 and d.is_global and not d.is_multicast and not d.is_reserved and d not in RED_6TO4


def cdn_de(ip, cnames=()):
    """El CDN de una IP: 'cloudflare' por sus rangos, el de RANGOS_CDN (CloudFront, Azure Front Door o Google) por los
    suyos, el del sufijo de cualquier nombre de su cadena CNAME (intermedio o final, con SUFIJOS_CDN o CDN_NUMERADOS), o
    None. `cnames` es un nombre o una lista de nombres."""
    direccion = ipaddress.ip_address(ip)
    if any(direccion in red for red in RANGOS_CLOUDFLARE):
        return 'cloudflare'
    for red, cdn in RANGOS_CDN:
        if direccion in red:
            return cdn
    if isinstance(cnames, str):
        cnames = (cnames,)
    for cname in sorted(c for c in cnames or () if c):
        for sufijo, cdn in SUFIJOS_CDN.items():
            if cname == sufijo or cname.endswith('.' + sufijo):
                return cdn
        for patron, cdn in CDN_NUMERADOS:
            if patron.fullmatch(cname):
                return cdn
    return None


# ---------------------------------------------------------------- activos y hallazgos

def _huella(codigo, dominio, activo, clave=''):
    """No lleva lo observado (tags, CPE ni nombres), así el hallazgo no se duplica entre escaneos."""
    return hashlib.sha256('|'.join((FUENTE, codigo, dominio, activo, clave)).encode('utf-8')).hexdigest()


def _cuantos(n, singular, plural):
    return '%d %s' % (n, singular if n == 1 else plural)


def _lista(nombres, maximo=5):
    """Los primeros `maximo` nombres y cuántos más, para un aviso que no crece con los nombres."""
    return ', '.join(nombres[:maximo]) + (' y %d más' % (len(nombres) - maximo) if len(nombres) > maximo else '')


def _donde(hosts):
    """El primer nombre de la IP y cuántos más tiene, para el título."""
    return hosts[0] if len(hosts) == 1 else '%s y %s' % (hosts[0], _cuantos(len(hosts) - 1, 'nombre más', 'nombres más'))


def _evidencia(titulo, ip, hosts, datos):
    """Lo común de la evidencia: InternetDB no da fechas, así que el dato puede ser viejo."""
    evidencia = {'title': titulo, 'ip': ip, 'hosts': hosts, 'tags': datos['tags'], 'fuente_datos': NOMBRE_INTERNETDB,
                 'vigencia': 'sin_fecha', 'fuente_sin_fecha': True, 'nota_vigencia': NOTA_SIN_FECHA}
    if datos['hostnames_ajenos']:
        evidencia['posible_dato_de_otro_dueno'] = True
    return evidencia


def hallazgo_puerto(codigo, dominio, servicio, ip, puerto, hosts, datos, ahora):
    """Un hallazgo de puerto sobre su activo service. Las características salen de la rúbrica (caracteristicas.py)."""
    if codigo in PROBABLES:
        titulo = TITULOS[codigo] % (puerto, PROBABLES[codigo][0][puerto], _donde(hosts))
    else:
        titulo = TITULOS[codigo] % (puerto, _donde(hosts))
    evidencia = dict(_evidencia(titulo, ip, hosts, datos), puerto=puerto, protocolo=protocolo(puerto),
                     protocolo_supuesto=True)
    if puerto in PUERTOS_INDUSTRIALES:
        evidencia['puerto_industrial'] = True
    if codigo in PROBABLES:
        # Lo que suele ser y no lo que es: sin conectarse no se sabe el servicio ni si pide autenticación (RC-224 y
        # RC-262)
        servicios, nota = PROBABLES[codigo]
        evidencia.update(servicio_probable=servicios[puerto], servicio_supuesto=True,
                         autenticacion='desconocida', nota_autenticacion=nota)
    return Hallazgo(codigo, CODIGOS[codigo], servicio, titulo, evidencia,
                    rubrica.calcular(codigo, 'service', evidencia, ahora), _huella(codigo, dominio, servicio),
                    partes=[ip])


def hallazgo_cve(dominio, ip, cve, hosts, datos, ahora):
    """known_vulnerability sobre el activo ip, con la CVE como clave. Shodan la deduce de la versión."""
    codigo = 'known_vulnerability'
    titulo = TITULO_CVE % (cve, _donde(hosts))
    evidencia = dict(_evidencia(titulo, ip, hosts, datos), cve=cve, cpes=datos['cpes'], deducida_por_version=True)
    return Hallazgo(codigo, CODIGOS[codigo], ip, titulo, evidencia, rubrica.calcular(codigo, 'ip', evidencia, ahora),
                    _huella(codigo, dominio, ip, cve), clave=cve, partes=[ip + PARTE_CVE])


def _servicios_de(h, etiquetas):
    """Los servicios de la API de host para la evidencia: los que llevan una de `etiquetas` en su banner o, si ninguno,
    todos, hasta MAX_SERVICIOS_EVIDENCIA, sin sus tags."""
    suyos = [s for s in h['servicios'] if set(s['tags']) & set(etiquetas)] or h['servicios']
    return [{k: s[k] for k in ('puerto', 'protocolo', 'producto', 'version', 'visto')}
            for s in suyos[:MAX_SERVICIOS_EVIDENCIA]]


def hallazgo_etiqueta(codigo, dominio, ip, hosts, etiquetas, d, h, ahora):
    """Un hallazgo de etiqueta (RC-220 y RC-337) sobre el activo ip, con la parte '<ip>/etiquetas'. Si la API de host
    trae la etiqueta (`h`), la evidencia lleva sus servicios con fecha y fuente_datos 'Shodan', y las que solo trae
    InternetDB van en etiquetas_internetdb, con nota_vigencia. Si solo la trae InternetDB (`d`), la evidencia es la de
    InternetDB, sin fecha."""
    titulo = TITULOS_ETIQUETA[codigo] % (', '.join(etiquetas), _donde(hosts))
    del_host = [t for t in etiquetas if t in h['tags']] if h else []
    if del_host:
        servicios = _servicios_de(h, del_host)
        evidencia = {'title': titulo, 'ip': ip, 'hosts': hosts, 'tags': h['tags'], 'fuente_datos': NOMBRE_HOST,
                     'servicios': servicios}
        fechas = [s['visto'] for s in servicios]
        if fechas:
            evidencia.update(vigencia='con_fecha', ultima_vez=max(fechas))
        else:
            evidencia.update(vigencia='sin_fecha', fuente_sin_fecha=True)
        solo_idb = [t for t in etiquetas if t not in del_host]
        if solo_idb:
            # Las que solo trae InternetDB no tienen fecha: van aparte, con su nota, y no se presentan como de la API de
            # host
            evidencia.update(etiquetas_internetdb=solo_idb, nota_vigencia=NOTA_SIN_FECHA)
        if (d and d.get('hostnames_ajenos')) or h.get('hostnames_ajenos'):
            evidencia['posible_dato_de_otro_dueno'] = True
    else:
        evidencia = _evidencia(titulo, ip, hosts, d)
        if h and h.get('hostnames_ajenos'):
            evidencia['posible_dato_de_otro_dueno'] = True
    evidencia['etiquetas'] = etiquetas
    return Hallazgo(codigo, CODIGOS[codigo], ip, titulo, evidencia, rubrica.calcular(codigo, 'ip', evidencia, ahora),
                    _huella(codigo, dominio, ip), partes=[ip + PARTE_ETIQUETAS])


def _aviso_ajenos_host(res, ip, h):
    """El aviso de los nombres de otro dominio que trae la API de host en `ip`, como el de InternetDB."""
    if h and h.get('hostnames_ajenos'):
        res.avisos.append('shodan: la API de host trae en %s %s de otro dominio: sus datos pueden ser de quien tuvo la '
                          'IP antes' % (ip, _cuantos(h['hostnames_ajenos'], 'nombre', 'nombres')))


def _etiquetas(res, dominio, ip, hosts, d, h, honeypot, ahora):
    """Los hallazgos de etiquetas de una IP, uno por código: con las etiquetas de InternetDB (`d`, o None si no
    respondió o dio 404) y las de la API de host (`h`, o None). Una IP honeypot no da ninguno."""
    if ip in honeypot:
        if d is None:
            res.avisos.append('shodan: la API de host marca %s como honeypot, no se sacan hallazgos de esa IP' % ip)
        return
    de_idb = set(d['tags']) if d else set()
    de_host = set(h['tags']) if h and not h.get('sin_datos') else set()
    for codigo in CODIGOS_ETIQUETA:
        etiquetas = sorted(t for t in de_idb | de_host if ETIQUETAS.get(t) == codigo)
        if etiquetas:
            res.hallazgos.append(hallazgo_etiqueta(codigo, dominio, ip, hosts, etiquetas, d, h if de_host else None,
                                                   ahora))


def _sin_cobertura(res, aviso):
    res.avisos.append(aviso)
    res.sin_cobertura = list(CODIGOS)
    return res


# ---------------------------------------------------------------- punto de entrada

def recolectar(dominio, cliente=None, ahora=None, propios=()):
    """Servicios y CVE que Shodan ya vio en las IP públicas del dominio. `propios` no se usa."""
    dominio = dominio.strip().lower().rstrip('.')
    res = Resultado(dominio, FUENTE)
    if not NOMBRE_VALIDO.fullmatch(dominio):
        res.estado, res.error = 'failed', 'dominio inválido: %s' % dominio
        return res
    cliente = cliente or crear_cliente('vivo', dominio)
    if cliente.modo == 'reproducir' and not cliente.hay_grabacion():
        return _sin_cobertura(res, SIN_GRABACION_DOMINIO)
    # Solo se tapa una llave con la forma de LLAVE_VALIDA, la única que se manda: una mal formada nunca sale en una URL,
    # y taparla estropearía los avisos y el error (con SHODAN_API_KEY=0, cada '0' sería '***')
    llave = getattr(cliente, 'llave', '') or ''
    llave = llave if LLAVE_VALIDA.fullmatch(llave) else ''
    tapada = None
    try:
        cliente.empezar()
        _revisar(res, cliente, dominio, ahora or datetime.now(timezone.utc))
    except FuenteNoResponde as e:
        if not llave:
            raise e from None
        tapada = _tapada(e, llave)   # se lanza fuera del except, sin el original en __context__ (host)
    finally:
        res.consultas = cliente.consultas
        if llave:   # otra vez, por si un aviso trajo la llave por otro camino
            res.avisos = [_tapar(a, llave) for a in res.avisos]
    if tapada is not None:
        raise tapada
    return res


def _nombres(dominio, certs):
    """La raíz y después, por nombre, los del dominio en los certificados, sin el '*.' de los comodines."""
    nombres = set()
    for cert in certs:
        for n in (cert.get('name_value') or '').split('\n'):
            n = n.strip().lower()
            n = _nombre(n[2:] if n.startswith('*.') else n)
            if n and n != dominio and en_alcance_nombre(n, dominio):
                nombres.add(n)
    return [dominio] + sorted(nombres)


def _partes_revisadas(ip, marca, d):
    """Las partes de una IP que quedaron revisadas completas (#23): la IP (sus puertos) y ip/cve (sus CVE). Las privadas
    y las de un CDN, que una corrida completa tampoco consulta, cuentan completas, igual que un 404 o el tag cdn de
    InternetDB. Un campo roto deja a medias lo que decide: ports la IP, vulns sus CVE y tags las dos (honeypot)."""
    if marca is not None:
        return [] if marca.get('internetdb') else [ip, ip + PARTE_CVE]
    if d is None:
        return []
    if d.get('sin_datos') or d.get('cdn'):
        return [ip, ip + PARTE_CVE]
    rotos = set(d['rotos'])
    if 'tags' in rotos:
        return []
    return ([ip] if 'ports' not in rotos else []) + (
        [ip + PARTE_CVE] if 'vulns' not in rotos else [])


def _etiquetas_revisadas(ip, marca, d, h, con_host):
    """True si la parte '<ip>/etiquetas' quedó revisada completa. Las privadas y las de un CDN, que una corrida completa
    tampoco consulta y que nunca dan hallazgos de etiquetas, cuentan revisadas, igual que el tag cdn de InternetDB y
    como sus otras partes (_partes_revisadas). Las demás, solo con la respuesta completa (sin 'rotos') de la API de
    host. Un 404, un error o el tope de tiempo no. Sin la llave, ninguna de las demás."""
    if marca is not None:
        return not marca.get('internetdb')
    if (d is not None and d.get('cdn')) or (h is not None and h.get('cdn')):
        return True
    return con_host and h is not None and not h.get('sin_datos') and not h['rotos']


def _revisar_host(res, cliente, consultar, datos):
    """La API de host por cada IP de `consultar` que InternetDB no marcó como CDN, con PAUSA_INTERNETDB entre una y
    otra. Devuelve {ip: limpio} de las que respondieron (también el 404). Un 429 o la llave rechazada (401 o 403) cortan
    las demás. Ninguna falla tumba la fuente: esas IP quedan sin revisar en sus etiquetas."""
    pedir = [ip for ip in consultar if not (datos.get(ip) or {}).get('cdn')]
    respuestas, sin_tiempo = {}, 0
    for i, ip in enumerate(pedir):
        if cliente.restante() < MIN_RESTANTE:
            sin_tiempo = len(pedir) - i
            # El tope de tiempo es una falla aunque no se haya pedido nada: 'grabar' no pisa la grabación anterior con
            # una sin estas host_*.json (el SinTiempo que sale de host() ya cuenta, en _consultar)
            cliente.fallas += 1
            break
        try:
            respuestas[ip] = cliente.host(ip, res.dominio, pausa=PAUSA_INTERNETDB if i else 0)
        except LimiteAlcanzado as e:
            res.avisos.append('%s. No se consultaron %s' % (e, _cuantos(len(pedir) - i, 'IP', 'IP')))
            break
        except SinTiempo:
            sin_tiempo = len(pedir) - i
            break
        except SinGrabacion as e:
            res.avisos.append('shodan: %s' % e)
        except RespuestaIlegible as e:
            if getattr(e, 'codigo', None) in (401, 403):
                res.avisos.append(LLAVE_RECHAZADA % (e.codigo, _cuantos(len(pedir) - i, 'IP', 'IP')))
                break
            res.avisos.append(str(e))
        except FuenteNoResponde as e:
            res.avisos.append(str(e))
    if sin_tiempo:
        res.avisos.append('shodan: el tiempo de la corrida cortó %s en la API de host' % _cuantos(sin_tiempo, 'IP', 'IP'))
    return respuestas


def _revisar(res, cliente, dominio, ahora):
    parcial = []    # por qué la cobertura quedó parcial
    con_host, aviso_llave = cliente.usa_host()
    if aviso_llave:
        res.avisos.append(aviso_llave)

    # 1. Nombres de Cert Spotter, más la raíz
    try:
        certs, completos = certspotter.certificados(cliente, dominio, max_paginas=PAGINAS_CT, intentos=INTENTOS_CT,
                                                    timeout=TIMEOUT_CT)
        ct_respondio = True
        if not completos:
            res.avisos.append('shodan: Cert Spotter no dio todas sus páginas, pueden faltar nombres del dominio')
            # Sin fallas ni emisiones ilegibles, solo se cortó en PAGINAS_CT: un tope determinista
            parcial.append('paginas' if not cliente.fallas and not cliente.raras_ct else 'ct')
    except FuenteNoResponde as e:
        certs, ct_respondio = [], False
        res.avisos.append('%s. Solo se revisó la raíz' % e)
        parcial.append('ct')
    nombres = _nombres(dominio, certs)
    if len(nombres) > MAX_NOMBRES:
        res.avisos.append('shodan: se resolvieron %d de %d nombres del dominio (MAX_NOMBRES)' % (MAX_NOMBRES, len(nombres)))
        nombres = nombres[:MAX_NOMBRES]
        parcial.append('nombres')

    # 2. Un A por nombre, sin tocar RESERVA_INTERNETDB: el lifetime, las esperas y el corte de cada A la descuentan
    por_ip, cnames, fallas_a, sin_grabar, sin_tiempo = {}, {}, [], [], 0
    cliente.reserva = RESERVA_INTERNETDB + (RESERVA_HOST if con_host else 0)
    try:
        for i, nombre in enumerate(nombres):
            if cliente.restante() < MIN_RESTANTE:
                sin_tiempo = len(nombres) - i
                break
            try:
                a = cliente.resolver_a(nombre)
            except SinTiempo:
                sin_tiempo = len(nombres) - i
                break
            except SinGrabacion:   # una grabación hecha con un tope de nombres más chico (antes de RC-55 era 10)
                sin_grabar.append(nombre)
                continue
            except FuenteNoResponde as e:
                fallas_a.append((nombre, str(e), getattr(e, 'sin_tiempo', False)))
                continue
            for ip in a['ips']:
                por_ip.setdefault(ip, set()).add(nombre)
                cnames.setdefault(ip, set()).update(a['cnames'])
    finally:
        cliente.reserva = 0
    # Un solo aviso para todos los A fallidos y otro para los no grabados: el orquestador guarda 10 avisos y el del
    # tiempo tiene que verse. El de los A dice cuántos se quedaron sin tiempo para otro intento, que no tienen su texto
    # y, si la reserva cortó el último nombre, no dejan otro aviso del tiempo (RC-166)
    if len(fallas_a) == 1:
        res.avisos.append(fallas_a[0][1])
    elif fallas_a:
        sin_otro = sum(1 for _, _, corto in fallas_a if corto)
        res.avisos.append('shodan: el DNS no respondió al A de %d nombres%s: %s' % (
            len(fallas_a), ' (%d sin tiempo para otro intento)' % sin_otro if sin_otro else '',
            _lista([n for n, _, _ in fallas_a])))
    if sin_grabar:
        res.avisos.append('shodan: la grabación no trae el A de %s, se grabó con otro tope de nombres: %s'
                          % (_cuantos(len(sin_grabar), 'nombre', 'nombres'), _lista(sin_grabar)))
        parcial.append('grabacion')
    if sin_tiempo:
        res.avisos.append('shodan: se acabó el tiempo de la corrida antes de resolver %s'
                          % _cuantos(sin_tiempo, 'nombre', 'nombres'))
        parcial.append('tiempo')
    if not ct_respondio and len(fallas_a) + len(sin_grabar) == len(nombres):
        raise FuenteNoResponde('shodan: no respondieron Cert Spotter ni el DNS de %s' % dominio)
    if fallas_a:
        parcial.append('a')
    todas_las_ip = not parcial   # sin nombres cortados ni A fallidos se conocen todas las IP del dominio

    # 3. Qué IP se consultan: públicas (consultable), fuera de un CDN en toda su cadena CNAME y fuera de un ASN de CDN.
    # La ubicación sale de la base local, sin red: las bases se piden una vez por corrida y solo si alguna IP es
    # ubicable (con solo IP privadas no se busca nada y el aviso de base faltante no diría nada cierto). Una IP sin ASN
    # conocido no se consulta: sin la base de ASN lo dice el aviso de base faltante (SIN_CDN_POR_ASN) y, con la base
    # abierta, SIN_ASN.
    ips = sorted(por_ip, key=ipaddress.ip_address)
    bases = geoip.bases_por_omision() if any(geoip.ubicable(ip) for ip in ips) else None
    ubicadas = {ip: geoip.ubicar(ip, bases) for ip in ips}
    aviso_geo = None if bases is None else geoip.aviso_sin_base(FUENTE, bases, sin_asn=SIN_CDN_POR_ASN)
    if aviso_geo:
        res.avisos.append(aviso_geo)
    marcas, consultar, sin_asn = {}, [], []
    for ip in ips:
        if not consultable(ip):
            marcas[ip] = {'no_publica': True}
            continue
        asn = ubicadas[ip]['asn']
        cdn = cdn_de(ip, cnames.get(ip, ())) or geoip.cdn_por_asn(asn)
        if cdn:
            marcas[ip] = {'cdn': cdn}
        elif isinstance(asn, bool) or not isinstance(asn, int):   # 'No disponible': no se sabe si es de un CDN
            marcas[ip] = {'internetdb': 'sin_asn'}
            sin_asn.append(ip)
        else:
            consultar.append(ip)
    if sin_asn:
        parcial.append('asn')
        if not (aviso_geo and bases.asn is None):   # sin la base, el aviso de base faltante ya lo dijo
            res.avisos.append(SIN_ASN % (_cuantos(len(sin_asn), 'IP', 'IP'), _lista(sin_asn)))
    # Las IP de la raíz van primero: con MAX_NOMBRES nombres las de los subdominios no la dejan fuera de MAX_IPS (RC-55)
    consultar.sort(key=lambda ip: (dominio not in por_ip[ip], ipaddress.ip_address(ip)))
    if len(consultar) > MAX_IPS:
        res.avisos.append('shodan: se consultaron %d de %d IP en InternetDB (MAX_IPS)' % (MAX_IPS, len(consultar)))
        for ip in consultar[MAX_IPS:]:
            marcas[ip] = {'internetdb': 'sin_consultar'}
        consultar = consultar[:MAX_IPS]
        parcial.append('ips')

    # 4. InternetDB por IP
    datos, fallas_red, sin_tiempo = {}, 0, 0
    for i, ip in enumerate(consultar):
        if cliente.restante() < MIN_RESTANTE:
            sin_tiempo = len(consultar) - i
            break
        try:
            datos[ip] = cliente.internetdb(ip, dominio, pausa=PAUSA_INTERNETDB if i else 0)
        except LimiteAlcanzado as e:
            res.avisos.append('%s. No se consultaron %s' % (e, _cuantos(len(consultar) - i, 'IP', 'IP')))
            parcial.append('limite')
            break
        except SinTiempo:
            sin_tiempo = len(consultar) - i
            break
        except SinGrabacion as e:
            res.avisos.append('shodan: %s' % e)
            parcial.append('grabacion')
        except RespuestaIlegible as e:
            res.avisos.append(str(e))
            parcial.append('ilegible')
        except FuenteNoResponde as e:
            fallas_red += 1
            res.avisos.append(str(e))
            parcial.append('red')
    if sin_tiempo:
        res.avisos.append('shodan: el tiempo de la corrida cortó %s en InternetDB, sin consultar o con la lectura a '
                          'medias' % _cuantos(sin_tiempo, 'IP', 'IP'))
        parcial.append('tiempo')
    if consultar and fallas_red == len(consultar):
        raise FuenteNoResponde('shodan: InternetDB no respondió por ninguna IP de %s' % dominio)
    if fallas_red and fallas_red + sin_tiempo == len(consultar):   # ninguna respondió: el tiempo cortó las demás
        raise FuenteNoResponde('shodan: InternetDB no respondió por ninguna IP de %s (por la red: %d, cortadas por '
                               'el tiempo: %d)' % (dominio, fallas_red, sin_tiempo))
    if not consultar and not parcial:
        res.avisos.append(SIN_IP)

    # 4b. La API de host por IP, solo con la llave (RC-337). Sus fallas no dejan parcial lo de InternetDB: solo las
    # etiquetas de esa IP quedan sin revisar
    host = _revisar_host(res, cliente, consultar, datos) if con_host else {}
    honeypot = {ip for ip in ips if 'honeypot' in (datos.get(ip) or {}).get('tags', ())
                or 'honeypot' in (host.get(ip) or {}).get('tags', ())}
    cdn_host = {ip for ip, h in host.items() if h.get('cdn')}

    # 5. Activos y hallazgos
    for ip in ips:
        hosts = sorted(por_ip[ip])
        atributos = dict({'hosts': hosts, 'fuente': FUENTE, 'origen': ORIGEN}, **ubicadas[ip])
        atributos.update(marcas.get(ip, {}))
        if ip in host:
            h = host[ip]
            atributos['shodan_host'] = ('sin_datos' if h.get('sin_datos') else 'descartada_cdn' if h.get('cdn') else {
                'tags': h['tags'], 'puertos': sorted({s['puerto'] for s in h['servicios']})})
        d = datos.get(ip)
        if ip in marcas:
            atributos.setdefault('internetdb', 'no_consultada')
            res.activos.append(Activo('ip', ip, atributos))
            continue
        if ip in cdn_host:
            # Como el tag cdn de InternetDB: de una IP de CDN solo queda que existe, sin sus datos ni hallazgos
            # (docs/politica_uso_etico.md, sección 2, punto 5)
            atributos.update(cdn='shodan_host', internetdb=('sin_respuesta' if d is None else 'sin_datos'
                                                            if d.get('sin_datos') else 'descartada_cdn'))
            res.activos.append(Activo('ip', ip, atributos))
            res.avisos.append('shodan: la API de host marca %s como CDN, se descartaron sus datos' % ip)
            continue
        if d is None:
            atributos['internetdb'] = 'sin_respuesta'
            res.activos.append(Activo('ip', ip, atributos))
            _aviso_ajenos_host(res, ip, host.get(ip))
            _etiquetas(res, dominio, ip, hosts, None, host.get(ip), honeypot, ahora)
            continue
        atributos['fuente_datos'] = NOMBRE_INTERNETDB   # solo en las IP que InternetDB sí respondió
        if d.get('sin_datos'):
            atributos['internetdb'] = 'sin_datos'
            res.activos.append(Activo('ip', ip, atributos))
            _aviso_ajenos_host(res, ip, host.get(ip))
            _etiquetas(res, dominio, ip, hosts, None, host.get(ip), honeypot, ahora)
            continue
        if d.get('cdn'):
            atributos.update(cdn='internetdb', internetdb='descartada_cdn')
            res.activos.append(Activo('ip', ip, atributos))
            res.avisos.append('shodan: InternetDB marca %s como CDN, se descartaron sus datos' % ip)
            continue
        atributos['internetdb'] = {'puertos': d['ports'], 'tags': d['tags'], 'cpes': d['cpes'], 'vulns': len(d['vulns']),
                                   'hostnames': d['hostnames'], 'hostnames_ajenos': d['hostnames_ajenos']}
        res.activos.append(Activo('ip', ip, atributos))
        if d['rotos']:   # lo que no se pudo leer no es 'nada abierto': esa IP queda revisada a medias
            res.avisos.append('shodan: InternetDB dio en %s datos que no se pueden leer (%s) y se ignoraron'
                              % (ip, ', '.join(d['rotos'])))
            parcial.append('ilegible')
        if d['hostnames_ajenos']:
            res.avisos.append('shodan: InternetDB trae en %s %s de otro dominio: sus datos pueden ser de quien tuvo la '
                              'IP antes' % (ip, _cuantos(d['hostnames_ajenos'], 'nombre', 'nombres')))
        _aviso_ajenos_host(res, ip, host.get(ip))
        if 'honeypot' in d['tags']:
            res.avisos.append('shodan: InternetDB marca %s como honeypot, no se sacan hallazgos de esa IP' % ip)
            continue
        if ip in honeypot:
            res.avisos.append('shodan: la API de host marca %s como honeypot, no se sacan hallazgos de esa IP' % ip)
            continue
        _etiquetas(res, dominio, ip, hosts, d, host.get(ip), honeypot, ahora)
        for puerto in d['ports']:
            servicio = '%s:%d/%s' % (ip, puerto, protocolo(puerto))
            res.activos.append(Activo('service', servicio, {
                'hosts': hosts, 'fuente': FUENTE, 'parent': ip, 'ip_address': ip, 'puerto': puerto,
                'protocolo': protocolo(puerto), 'protocolo_supuesto': True, 'fuente_datos': NOMBRE_INTERNETDB}))
            codigo = codigo_de_puerto(puerto)
            if codigo:
                res.hallazgos.append(hallazgo_puerto(codigo, dominio, servicio, ip, puerto, hosts, d, ahora))
        # d['vulns'] va de la más reciente a la más vieja: se reportan las MAX_CVE más recientes. Las omitidas siguen
        # ahí: van en omitidos, para que el orquestador no cierre las que se reportaron antes (#23)
        res.hallazgos += [hallazgo_cve(dominio, ip, cve, hosts, d, ahora) for cve in d['vulns'][:MAX_CVE]]
        res.omitidos += [_huella('known_vulnerability', dominio, ip, cve) for cve in d['vulns'][MAX_CVE:]]
        if len(d['vulns']) > MAX_CVE:
            res.avisos.append('shodan: %s trae %d CVE, se reportan las %d más recientes y se omitieron %d'
                              % (ip, len(d['vulns']), MAX_CVE, len(d['vulns']) - MAX_CVE))

    # 6. Cobertura. Las etiquetas quedan revisadas solo con la API de host completa en todas las IP y sin otro recorte.
    # Si no, sus códigos sin hallazgos van a sin_cobertura y, si alguno trae hallazgos, revisados y sin_revisar llevan
    # la parte de etiquetas de cada IP, para no cerrar lo de una IP que no se revisó (#23)
    res.avisos.append(LIMITES_CON_LLAVE if con_host else LIMITES)
    con_hallazgos = {h.codigo for h in res.hallazgos}
    etiquetas_ok = [ip for ip in ips if _etiquetas_revisadas(ip, marcas.get(ip), datos.get(ip), host.get(ip), con_host)]
    etiquetas_completas = con_host and not parcial and len(etiquetas_ok) == len(ips)
    if con_host and not etiquetas_completas:
        res.avisos.append(ETIQUETAS_PARCIAL % (len(etiquetas_ok), len(ips)))
    sin_etiquetas = [] if etiquetas_completas else [c for c in SIN_LLAVE if c not in con_hallazgos]
    res.sin_cobertura = sin_etiquetas
    # Con la llave, una IP que la API de host revisó completa cuenta como revisada en sus etiquetas aunque ninguna IP
    # traiga hallazgos de etiqueta: así no depende de otra IP que se cierre lo suyo (docs/codigos_reglas.md)
    if parcial or (not etiquetas_completas and (con_hallazgos & set(SIN_LLAVE) or (con_host and etiquetas_ok))):
        res.sin_cobertura = ([c for c in CODIGOS_PUERTOS if c not in con_hallazgos] if parcial else []) + sin_etiquetas
        if parcial:
            res.avisos.append('%s, se revisaron %d de %d IP del dominio en InternetDB' % (
                PARCIAL, len(datos), len(consultar) + sum(1 for m in marcas.values() if m.get('internetdb'))))
        res.revisados = [parte for ip in ips for parte in
                         _partes_revisadas(ip, marcas.get(ip), {'cdn': True} if ip in cdn_host else datos.get(ip))
                         + ([ip + PARTE_ETIQUETAS] if ip in etiquetas_ok else [])]
        if todas_las_ip:
            res.sin_revisar = [parte for ip in ips for parte in (ip, ip + PARTE_CVE, ip + PARTE_ETIQUETAS)
                               if parte not in res.revisados]
    # Sin la API de host, las etiquetas faltan por la llave. Con ella, lo que falte es cobertura parcial (RC-229)
    res.sin_llave = [] if con_host else [c for c in sin_etiquetas if c in res.sin_cobertura]
    # Una corrida con fallas no pisa una grabación completa (como github.py con SIN_CUOTA). El aviso va primero, para
    # que entre en los 10 que guarda el orquestador
    if cliente.modo == 'grabar' and cliente.degradada(parcial):
        res.avisos.insert(0, NO_SE_GRABO)
    else:
        cliente.terminar()
    return res


# ---------------------------------------------------------------- línea de comandos

SEVERIDAD_ES = {'critical': 'crítica', 'high': 'alta', 'medium': 'media', 'low': 'baja'}


def resumen(res):
    """Líneas para la terminal."""
    lineas = ['%s · %s · %s · %s' % (res.dominio, FUENTE, res.estado, _cuantos(res.consultas, 'consulta', 'consultas'))]
    if res.error:
        lineas.append('error: %s' % res.error)
    for a in res.activos:
        if a.tipo == 'ip':
            i = a.atributos.get('internetdb')
            estado = ('puertos %s' % (', '.join(map(str, i['puertos'])) or 'ninguno')) if isinstance(i, dict) else i
            marca = ' · CDN %s' % a.atributos['cdn'] if a.atributos.get('cdn') else ''
            lineas.append('IP %s (%s) · %s%s' % (a.valor, ', '.join(a.atributos['hosts']), estado, marca))
    if res.hallazgos:
        lineas.append(_cuantos(len(res.hallazgos), 'hallazgo:', 'hallazgos:'))
        lineas += ['  [%s] %s' % (SEVERIDAD_ES.get(h.severidad, h.severidad), h.titulo) for h in res.hallazgos]
    elif res.estado == 'succeeded':
        lineas.append('Sin hallazgos.')
    if res.sin_cobertura:  # no es lo mismo que 0 hallazgos
        lineas.append('Cobertura parcial: no se revisaron %s.' % ' ni '.join(res.sin_cobertura))
    lineas += ['aviso: %s' % a for a in res.avisos]
    return lineas


def codigo_salida(res):
    """0 si la corrida fue completa, 1 si el resultado queda en 'failed', 2 si la cobertura quedó parcial y 3 si
    --grabar no escribió por una falla (NO_SE_GRABO). Los avisos fijos LIMITES y LIMITES_CON_LLAVE y los códigos de
    SIN_LLAVE, que salen en toda corrida sin la API de host completa, no cuentan. Tampoco revisados cuando solo le
    faltan partes de etiquetas: es la misma cobertura de SIN_LLAVE, por IP. Una corrida a la que le falta otra parte
    (un puerto o una CVE) siempre trae el aviso PARCIAL (recolectar, paso 6)."""
    if res.estado == 'failed':
        return 1
    if NO_SE_GRABO in res.avisos:
        return 3
    parcial = set(res.sin_cobertura) - set(SIN_LLAVE) or any(a.startswith(PARCIAL) for a in res.avisos)
    return 2 if parcial else 0


def _main(argv=None):
    # En Windows, cuando la salida no es la consola (Git Bash, una tubería), Python usa cp1252 y los acentos se rompen.
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    p = argparse.ArgumentParser(description='Servicios, CVE y etiquetas que Shodan ya vio en las IP públicas del dominio '
                                            '(InternetDB y, con SHODAN_API_KEY, la API de host)')
    p.add_argument('dominio')
    modo = p.add_mutually_exclusive_group()
    modo.add_argument('--grabar', action='store_true',
                      help='empieza una grabación nueva en cirdan/recolectores/respuestas_grabadas/shodan/<dominio>/')
    modo.add_argument('--reproducir', action='store_true', help='usa solo la grabación, sin red')
    p.add_argument('--json', action='store_true', help='imprime el resultado completo en JSON')
    a = p.parse_args(argv)
    dominio = a.dominio.strip().lower().rstrip('.')
    if not NOMBRE_VALIDO.fullmatch(dominio):  # también evita que '..' o '/' saquen la carpeta de respuestas_grabadas
        p.error('dominio inválido: %s' % a.dominio)
    modo = 'grabar' if a.grabar else 'reproducir' if a.reproducir else 'vivo'
    if modo != 'reproducir' and not _en_vivo_permitido(dominio):
        p.error('%s no está en DOMINIOS_EN_VIVO: Shodan solo se consulta en vivo, o se graba, con la carta vigente del '
                'dominio. Usa --reproducir' % dominio)
    cliente = crear_cliente(modo, dominio)
    try:
        res = recolectar(dominio, cliente)
    except FuenteNoResponde as e:
        res = Resultado(dominio, FUENTE, estado='failed', consultas=cliente.consultas, error=str(e))
    if a.json:
        print(json.dumps(res.a_dict(), ensure_ascii=False, indent=1))
    else:
        print('\n'.join(resumen(res)))
    return codigo_salida(res)


if __name__ == '__main__':
    sys.exit(_main())

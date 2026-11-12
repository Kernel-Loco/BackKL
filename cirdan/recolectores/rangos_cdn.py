"""Arma rangos_cdn.json, los rangos IPv4 publicados de los CDN de las nubes mixtas (#17, RC-49, H11 de la auditoría del
12 nov), desde los archivos que publica cada nube. No baja nada: los archivos se bajan aparte, una vez y con el OK de
la persona, y el recolector de Shodan lee solo el JSON que queda en el repo, sin red.

Un ASN mixto de nube y CDN (Amazon, Microsoft, Google) no basta para decir que una IP es de un CDN (geoip.CDN_POR_ASN
no los lista), pero sus rangos publicados sí separan el borde del CDN de las VM de la empresa:
- cloudfront: los prefijos IPv4 con service CLOUDFRONT de https://ip-ranges.amazonaws.com/ip-ranges.json.
- azure_front_door: los prefijos IPv4 de la etiqueta AzureFrontDoor.Frontend del JSON semanal de Service Tags de Azure
  (página de descarga 56519 de microsoft.com, archivo ServiceTags_Public_AAAAMMDD.json en download.microsoft.com).
- google: los prefijos IPv4 de https://www.gstatic.com/ipranges/goog.json menos los de
  https://www.gstatic.com/ipranges/cloud.json, que son los de los clientes de Google Cloud. Quedan los bordes y
  servicios propios de Google. Cloud CDN en un balanceador de Google Cloud
  usa una IP de cloud.json, igual que una VM, y no se puede separar con estos archivos: queda fuera (shodan.LIMITES).

Para volver a generarlo, desde la raíz de BackKL, con los cuatro archivos ya bajados:
    python -m cirdan.recolectores.rangos_cdn <ip-ranges.json> <ServiceTags_Public_AAAAMMDD.json> <goog.json> \\
        <cloud.json> AAAA-MM-DD > cirdan/recolectores/rangos_cdn.json
La fecha es la de la descarga. Los rangos cambian (Azure publica cada semana): la fecha dice de cuándo son.
"""
import ipaddress
import json
import sys

URL_AWS = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
URL_AZURE = 'https://www.microsoft.com/en-us/download/details.aspx?id=56519'
URL_GOOGLE = 'https://www.gstatic.com/ipranges/goog.json'
URL_GOOGLE_CLOUD = 'https://www.gstatic.com/ipranges/cloud.json'
ETIQUETA_AZURE = 'AzureFrontDoor.Frontend'
SERVICIO_AWS = 'CLOUDFRONT'


def _ipv4(prefijos):
    """Las redes IPv4 globales de una lista de textos, unidas y en orden. Las IPv6 se saltan (InternetDB es IPv4)."""
    redes = []
    for p in prefijos:
        red = ipaddress.ip_network(p)
        if red.version == 4 and red.is_global:
            redes.append(red)
    return list(ipaddress.collapse_addresses(redes))


def _menos(redes, quitar):
    """Las direcciones de `redes` que no están en ninguna de `quitar`, como redes unidas y en orden."""
    quedan = list(redes)
    for q in quitar:
        siguen = []
        for r in quedan:
            if not r.overlaps(q):
                siguen.append(r)
            elif not q.supernet_of(r):
                siguen.extend(r.address_exclude(q))
        quedan = siguen
    return list(ipaddress.collapse_addresses(quedan))


def armar(aws, azure, google, google_cloud, fecha):
    """El contenido de rangos_cdn.json a partir de los cuatro JSON ya leídos y la fecha de descarga (AAAA-MM-DD)."""
    frontales = [v for v in azure['values'] if v.get('name') == ETIQUETA_AZURE]
    if len(frontales) != 1:
        raise ValueError('el JSON de Azure no trae una sola etiqueta %s' % ETIQUETA_AZURE)
    fd = frontales[0]['properties']
    rangos = {
        'cloudfront': _ipv4(p['ip_prefix'] for p in aws['prefixes'] if p.get('service') == SERVICIO_AWS),
        'azure_front_door': _ipv4(fd['addressPrefixes']),
        'google': _menos(_ipv4(p['ipv4Prefix'] for p in google['prefixes'] if 'ipv4Prefix' in p),
                         _ipv4(p['ipv4Prefix'] for p in google_cloud['prefixes'] if 'ipv4Prefix' in p)),
    }
    if not all(rangos.values()):
        raise ValueError('un CDN quedó sin rangos: %s' % sorted(k for k, v in rangos.items() if not v))
    return {
        'procedencia': {
            'descargado': fecha,
            'cloudfront': {'url': URL_AWS, 'service': SERVICIO_AWS, 'syncToken': aws['syncToken'],
                           'createDate': aws['createDate']},
            'azure_front_door': {'url': URL_AZURE, 'etiqueta': ETIQUETA_AZURE, 'changeNumber': azure['changeNumber'],
                                 'changeNumber_etiqueta': fd['changeNumber'], 'cloud': azure['cloud']},
            'google': {'url': URL_GOOGLE, 'menos': URL_GOOGLE_CLOUD, 'syncToken': google['syncToken'],
                       'creationTime': google['creationTime'], 'syncToken_cloud': google_cloud['syncToken']},
        },
        'rangos': {cdn: [str(r) for r in redes] for cdn, redes in rangos.items()},
    }


def main(argv):
    if len(argv) != 5:
        sys.exit('uso: python -m cirdan.recolectores.rangos_cdn <aws> <azure> <goog> <cloud> AAAA-MM-DD')
    leidos = []
    for ruta in argv[:4]:
        with open(ruta, encoding='utf-8') as f:
            leidos.append(json.load(f))
    sys.stdout.write(json.dumps(armar(*leidos, argv[4]), ensure_ascii=False, indent=1, sort_keys=True) + '\n')


if __name__ == '__main__':
    main(sys.argv[1:])

"""Nombres internos que un certificado deja a la vista en Certificate Transparency (#14, RC-218).

Un certificado público de dev.acme.mx o de jenkins.acme.mx dice a cualquiera, sin tocar los servidores, que la empresa
tiene un entorno de pruebas o una herramienta interna con nombre en internet. crtsh.py da cert_internal_name con un
nombre del dominio autorizado que lleva una de estas etiquetas.

La lista es corta y va versionada aquí (VERSION). Cuenta la etiqueta entera o una de sus partes separadas por guion:
dev-api.acme.mx sí, developer.acme.mx no, y tampoco dev2.acme.mx. Solo se miran las etiquetas a la izquierda del
dominio autorizado: en dev.acme.mx con el dominio dev.mx no cuenta, porque dev es la marca de la empresa. Una
etiqueta en Punycode (xn--) no cuenta: partirla por guion daría pedazos de la codificación, no palabras.
Al cambiar la lista sube VERSION, que va en la evidencia de cada hallazgo.
"""
VERSION = 1

ETIQUETAS = frozenset((
    # entornos que no son producción
    'dev', 'desa', 'desarrollo', 'staging', 'stage', 'stg', 'test', 'testing', 'pruebas', 'qa', 'uat', 'preprod',
    'sandbox',
    # acceso remoto y red interna
    'vpn', 'intranet', 'internal', 'interno', 'admin',
    # herramientas internas de desarrollo y operación
    'jenkins', 'gitlab', 'jira', 'confluence', 'grafana', 'kibana', 'prometheus', 'sonarqube', 'nexus', 'artifactory',
    'argocd', 'portainer', 'phpmyadmin', 'pgadmin',
))


def etiqueta_interna(nombre, dominio):
    """La primera etiqueta de la lista que lleva `nombre` a la izquierda de `dominio`, entera o como parte separada por
    guion, o None. `nombre` y `dominio` van en minúsculas y sin el punto final, como los deja crtsh._nombres."""
    if not nombre.endswith('.' + dominio):
        return None
    for etiqueta in nombre[:-len(dominio) - 1].split('.'):
        if etiqueta.startswith('xn--'):  # Punycode: sus guiones no separan palabras ('xn--test-epa' es 'testé')
            continue
        if etiqueta in ETIQUETAS:
            return etiqueta
        for parte in etiqueta.split('-'):
            if parte in ETIQUETAS:
                return parte
    return None

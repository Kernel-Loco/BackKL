"""Pide un escaneo desde la terminal y muestra en español si se aceptó o por qué no.

    python -m cirdan.orquestador olmardo.com                     # dominio de prueba, en vivo
    python -m cirdan.orquestador partner-example.com --org ACME  # rechazado: sin autorización
    python -m cirdan.orquestador olmardo.com --modo reproducir   # recolectores con respuestas grabadas

Con Docker: docker compose exec api python -m cirdan.orquestador olmardo.com
Código de salida: 0 escaneo aceptado, 3 rechazado.
"""
import argparse
import sys

from cirdan.orquestador import correr, marcar_fallido, solicitar

EMPRESAS = {
    'OLMARDO': '20000000-0000-4000-8000-000000000003',  # Grupo Olmardo, dominio de prueba (semilla 002)
    'ACME': '20000000-0000-4000-8000-000000000001',
    'BETA': '20000000-0000-4000-8000-000000000002',
}
ESTADOS = {'succeeded': 'correcto', 'retrying': 'falló, se reintentará', 'failed': 'falló'}


def main(argv=None):
    p = argparse.ArgumentParser(prog='python -m cirdan.orquestador', description='Pide un escaneo de un dominio autorizado.')
    p.add_argument('dominio')
    p.add_argument('--org', default='OLMARDO', help='OLMARDO, ACME, BETA o el uuid de la organización')
    p.add_argument('--modo', default='vivo', choices=['vivo', 'grabar', 'reproducir'])
    args = p.parse_args(argv)
    org = EMPRESAS.get(args.org.upper(), args.org)

    solicitud = solicitar(org, args.dominio, trigger='on_demand')
    if not solicitud.aceptada:
        print('RECHAZADO ·', solicitud.fqdn)
        print(solicitud.detalle)
        print('Motivos:', ', '.join(solicitud.motivos))
        return 3

    print('ACEPTADO ·', solicitud.fqdn, '· autorización vigente y TXT verificado')
    print('Escaneo', solicitud.scan_id)
    if args.modo == 'vivo':
        print('En vivo, una fuente que falla se reintenta a 1, 5 y 25 minutos: puede tardar más de media hora.')
    try:
        resumen = correr(org, solicitud.scan_id, solicitud.fqdn, modo=args.modo)
    except Exception as e:
        marcar_fallido(org, solicitud.scan_id, e)
        raise
    for r in resumen['sources']:
        print('  %-8s %s · %d activos, %d hallazgos%s%s' % (
            r['source'], ESTADOS.get(r['status'], r['status']), r['activos'], r['hallazgos'],
            ' · sin cobertura: ' + ', '.join(r['sin_cobertura']) if r['sin_cobertura'] else '',
            ' · ' + r['error'] if r['error'] else ''))
        for aviso in r['avisos']:  # por ejemplo, que Cert Spotter no respondió aunque la fuente quedó correcta
            if aviso != r['error']:
                print('    aviso:', aviso)
        if r.get('avisos_omitidos'):  # la corrida guarda solo los primeros 10
            print('    y %d %s' % (r['avisos_omitidos'], 'aviso más' if r['avisos_omitidos'] == 1 else 'avisos más'))
    print('Resultado:', resumen['status'], '·', resumen['stats'])
    return 0


if __name__ == '__main__':
    sys.exit(main())

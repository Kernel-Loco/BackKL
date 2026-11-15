#!/usr/bin/env bash
# Restaura un respaldo de respaldar.sh en una base NUEVA (#115, RC-233). Nunca hace DROP DATABASE ni escribe
# sobre cirdan: si la base ya existe, se niega.
#
#   AGE_IDENTIDAD=<archivo de la llave privada de age> db/respaldo/restaurar.sh <respaldo.dump.age> <contenedor> <base_nueva>
#
# Con AGE_IDENTIDAD=- la llave llega por stdin (así no toca el disco), y el respaldo va siempre como archivo.
# El contenedor es el de una base de Postgres 16 con los roles ya creados por db/init (cirdan_app y su
# contraseña no vienen en el respaldo). En Windows se corre en Git Bash: en PowerShell 5.1 la tubería
# cambia los bytes y deja el respaldo inservible.
set -Eeuo pipefail
export LC_ALL=C

falla() { echo "restaurar: ERROR: $*" >&2; exit 1; }

[ $# -eq 3 ] || falla "uso: AGE_IDENTIDAD=<llave> $0 <respaldo.dump.age> <contenedor> <base_nueva>"
respaldo=$1 contenedor=$2 base=$3
identidad=${AGE_IDENTIDAD:-}

[ -n "$identidad" ] || falla "falta AGE_IDENTIDAD"
[ "$identidad" = - ] || [ -f "$identidad" ] || falla "no existe la llave $identidad"
[ -f "$respaldo" ] || falla "no existe $respaldo"
[[ $contenedor =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || falla "contenedor no válido"
[[ $base =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || falla "la base nueva va en minúsculas, dígitos y _"
case $base in
  cirdan|postgres|template0|template1) falla "no se restaura sobre $base: usa otro nombre" ;;
esac
command -v age >/dev/null || falla "falta age"

psql_c() {
  MSYS_NO_PATHCONV=1 docker exec -i "$contenedor" sh -c 'exec psql -U "$POSTGRES_USER" -d postgres -X -q -At -v ON_ERROR_STOP=1'
}
existe=$(printf "SELECT count(*) FROM pg_database WHERE datname = '%s';\n" "$base" | psql_c)
[ "$existe" = 0 ] || falla "la base $base ya existe: este script no la borra ni la pisa"
printf 'CREATE DATABASE "%s";\n' "$base" | psql_c
echo "restaurar: base $base creada en $contenedor"

# --single-transaction y --exit-on-error: si algo falla, la base nueva queda vacía, no a medias.
age -d -i "$identidad" "$respaldo" \
  | MSYS_NO_PATHCONV=1 docker exec -i -e BASE="$base" "$contenedor" \
      sh -c 'exec pg_restore -U "$POSTGRES_USER" -d "$BASE" --no-password --single-transaction --exit-on-error'
echo "restaurar: $respaldo restaurado en $base. Compara con: db/respaldo/comparar.sh $contenedor cirdan $base"

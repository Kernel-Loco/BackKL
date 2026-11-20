#!/usr/bin/env bash
# Restaura un respaldo de respaldar.sh en una base NUEVA (#115, RC-233). Nunca hace DROP DATABASE ni escribe
# sobre cirdan: si la base ya existe, se niega.
#
#   AGE_IDENTIDAD=<archivo de la llave privada de age, o -> db/respaldo/restaurar.sh <respaldo.dump.age> <contenedor> <base_nueva>
#
# AGE_IDENTIDAD es la RUTA del archivo de la llave, nunca la llave. Con AGE_IDENTIDAD=- la llave llega por stdin
# (así no toca el disco), y el respaldo va siempre como archivo.
# El contenedor es el de una base de Postgres 16 con los roles ya creados por db/init (cirdan_app y su
# contraseña no vienen en el respaldo). En Windows se corre en Git Bash: en PowerShell 5.1 la tubería
# cambia los bytes y deja el respaldo inservible.
set -Eeuo pipefail
export LC_ALL=C

falla() { echo "restaurar: ERROR: $*" >&2; exit 1; }

[ $# -eq 3 ] || falla "uso: AGE_IDENTIDAD=<archivo de la llave o -> $0 <respaldo.dump.age> <contenedor> <base_nueva>"
respaldo=$1 contenedor=$2 base=$3
identidad=${AGE_IDENTIDAD:-}
llave=

# Los mensajes nunca repiten el valor de AGE_IDENTIDAD: si alguien pegó ahí la llave, saldría en la terminal.
[ -n "$identidad" ] || falla "falta AGE_IDENTIDAD (la ruta del archivo de la llave, o -)"
case $identidad in
  *AGE-SECRET-KEY-*) falla "AGE_IDENTIDAD lleva la llave misma: tiene que ser la ruta de su archivo, o - para stdin" ;;
esac
if [ "$identidad" = - ]; then
  llave=$(cat)
  [[ $llave == *AGE-SECRET-KEY-1* ]] || falla "stdin no trae una llave privada de age"
else
  [ -f "$identidad" ] || falla "no existe el archivo de la llave de AGE_IDENTIDAD"
fi
[ -f "$respaldo" ] || falla "no existe $respaldo"
[[ $contenedor =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || falla "contenedor no válido"
[[ $base =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || falla "la base nueva va en minúsculas, dígitos y _"
case $base in
  cirdan|postgres|template0|template1) falla "no se restaura sobre $base: usa otro nombre" ;;
esac
command -v age >/dev/null || falla "falta age"

descifrar() {
  if [ "$identidad" = - ]; then
    printf '%s\n' "$llave" | age -d -i - "$respaldo"
  else
    age -d -i "$identidad" "$respaldo"
  fi
}
psql_c() {
  MSYS_NO_PATHCONV=1 docker exec -i "$contenedor" sh -c 'exec psql -U "$POSTGRES_USER" -d postgres -X -q -At -v ON_ERROR_STOP=1'
}

existe=$(printf "SELECT count(*) FROM pg_database WHERE datname = '%s';\n" "$base" | psql_c)
[ "$existe" = 0 ] || falla "la base $base ya existe: este script no la borra ni la pisa"

# Antes de crear la base: age revisa la autenticación de cada bloque, así que una llave equivocada o un archivo
# cortado fallan aquí y no queda ninguna base vacía que estorbe al reintentar.
descifrar > /dev/null || falla "no se pudo descifrar $respaldo (otra llave o archivo incompleto). No se creó ninguna base."

printf 'CREATE DATABASE "%s";\n' "$base" | psql_c
echo "restaurar: base $base creada en $contenedor"

# --single-transaction y --exit-on-error: si algo falla, la base nueva queda vacía, no a medias.
if ! descifrar | MSYS_NO_PATHCONV=1 docker exec -i -e BASE="$base" "$contenedor" \
       sh -c 'exec pg_restore -U "$POSTGRES_USER" -d "$BASE" --no-password --single-transaction --exit-on-error'; then
  falla "pg_restore falló: la base $base quedó vacía y este script no la borra. Reintenta con otro nombre."
fi
# pg_dump sin --create no guarda los permisos de la base. La migración 004 le quita TEMPORARY a PUBLIC, y una base
# recién creada lo trae puesto: se quita igual. conteos.sql compara esos permisos con los de la original.
printf 'REVOKE TEMPORARY ON DATABASE "%s" FROM PUBLIC;\n' "$base" | psql_c
echo "restaurar: $respaldo restaurado en $base."
echo "restaurar: para comparar, corre db/respaldo/conteos.sql como postgres en la base original (la de la VM) y en $base, y compara las dos salidas. comparar.sh solo sirve si la original está en este mismo contenedor."

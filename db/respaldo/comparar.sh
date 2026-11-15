#!/usr/bin/env bash
# Compara dos bases del mismo contenedor con conteos.sql: filas por tabla, RLS, FORCE y políticas (#115, RC-233).
#   db/respaldo/comparar.sh <contenedor> <base_original> <base_restaurada>
# Sale con 0 si son iguales. Solo lee.
set -Eeuo pipefail
export LC_ALL=C
falla() { echo "comparar: ERROR: $*" >&2; exit 1; }
[ $# -eq 3 ] || falla "uso: $0 <contenedor> <base_original> <base_restaurada>"
contenedor=$1
[[ $contenedor =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || falla "contenedor no válido"
for b in "$2" "$3"; do [[ $b =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || falla "base no válida: $b"; done
sql="$(dirname "$0")/conteos.sql"

conteos() {
  MSYS_NO_PATHCONV=1 docker exec -i -e BASE="$1" "$contenedor" \
    sh -c 'exec psql -U "$POSTGRES_USER" -d "$BASE" -X -q -At -v ON_ERROR_STOP=1' < "$sql" | tr -d '\r'
}
a=$(conteos "$2")
b=$(conteos "$3")
[ -n "$a" ] || falla "$2 no tiene tablas"
if [ "$a" = "$b" ]; then
  echo "comparar: iguales, $(printf '%s\n' "$a" | wc -l) tablas"
  echo "comparar: con RLS, FORCE y política: $(printf '%s\n' "$a" | grep -c '|t|t|[1-9]')"
else
  diff <(printf '%s\n' "$a") <(printf '%s\n' "$b") || true
  falla "$2 y $3 no son iguales"
fi

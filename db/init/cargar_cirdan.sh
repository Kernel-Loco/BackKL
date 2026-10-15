#!/bin/sh
# Carga la base `cirdan` la primera vez que arranca el contenedor de PostgreSQL
# (el volumen está vacío). Después no vuelve a correr: para empezar de cero,
# `docker compose down -v` y `docker compose up`.
set -eu

echo "cirdan: creando la base"
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -c "CREATE DATABASE cirdan;"

for f in /cirdan-db/migraciones/*.sql; do
  echo "cirdan: migración $(basename "$f")"
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d cirdan -f "$f"
done

# La contraseña viaja como variable de psql, nunca en la línea de comandos.
echo "cirdan: contraseña del rol cirdan_app"
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d cirdan -v pw="$CIRDAN_APP_PASSWORD" <<'SQL'
ALTER ROLE cirdan_app PASSWORD :'pw';
SQL

for f in /cirdan-db/semillas/*.sql; do
  echo "cirdan: semilla $(basename "$f")"
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d cirdan -f "$f"
done
echo "cirdan: base lista"

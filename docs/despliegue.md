# Despliegue de LowTide (#49, RC-91)

La VM y el plan B levantan la misma pila: `docker-compose.yml` más `docker-compose.despliegue.yml`. El segundo archivo suma el portal (FrontKL) y Cloudflare Tunnel. Ningún puerto queda publicado en el host, ni siquiera en 127.0.0.1. Lo que entra por lowtidesec.com llega por el túnel al portal, y el portal reenvía `/api/v1` a la API. La API no tiene nombre público.

```
navegador → Cloudflare (HTTPS) → cloudflared ─borde─ portal ─interna─ api ─default─ db, valkey
                                      └─salida─ Cloudflare
```

## Antes de levantar

1. FrontKL clonado junto a BackKL (`../FrontKL`), o su ruta en `PORTAL_DIR`.
2. `.env` copiado de `.env.example`, con contraseñas propias y además:
   - `ALLOWED_ORIGINS=https://lowtidesec.com,https://www.lowtidesec.com`. Van los dos porque el túnel publica los dos nombres y el navegador manda el Origin del nombre que abrió: sin el de www, la API responde 403 al login que llega por www. Sin la variable la pila no arranca. También apaga las cuentas de demo (RC-287).
   - `TUNNEL_TOKEN`, el token del túnel de Cloudflare. Sin él la pila no arranca. Nunca va en git.
   - `COMPOSE_FILE=docker-compose.yml:docker-compose.despliegue.yml` y `COMPOSE_PATH_SEPARATOR=:`. Con eso cualquier `docker compose` de esa carpeta usa los dos archivos, aunque se escriba sin los `-f`. Sin ellos, un `docker compose up -d --build` recrea la API con la config de desarrollo, sin la red interna, y lowtidesec.com responde 500 en `/api/v1`. `COMPOSE_PATH_SEPARATOR=:` hace falta en Windows (plan B), donde el separador por omisión es `;`. En Linux no estorba.
   - `DOMINIOS_EN_VIVO` y `ORGS_GITHUB_DECLARADAS` según las cartas vigentes.
3. En Cloudflare:
   - Zero Trust: el túnel publica `lowtidesec.com` y `www.lowtidesec.com` hacia `http://portal:3000`.
   - SSL/TLS > Edge Certificates: 'Always Use HTTPS' prendido. Sin él el portal también responde por `http://` y el formulario de login manda la contraseña sin cifrar hasta Cloudflare (la API la rechaza después por el Origin, pero ya viajó). Se comprueba con `curl -sI http://lowtidesec.com/login` y `curl -sI http://www.lowtidesec.com/login`: los dos responden 301 con `Location: https://...`. HSTS queda para RC-89.
4. `docker login` con `DOCKERHUB_USERNAME` y `DOCKERHUB_TOKEN` de la cuenta 'lowtidesec' (solo lectura).
5. Docker Engine reciente, con Compose 2.24 o más nuevo. Las redes `borde` e `interna` usan `gateway_mode_ipv4=isolated` y los puertos se quitan con `ports: !reset []`. Un Docker viejo rechaza la opción de red y `up` falla: nunca levanta la pila sin el aislamiento. Se probó con Docker Engine 29.8 y Compose 5.5.

## Levantar

Con `COMPOSE_FILE` en el `.env` (paso 2), desde la carpeta de BackKL:

```bash
docker compose up -d --build
docker compose logs demo-accounts
```

La segunda línea tiene que decir 'DEMO_ACCOUNTS no es true: se apagan las cuentas de demo.' y luego 'cuenta de demo apagada:' con cada una de las 5 cuentas de `CUENTAS` de `cirdan/auth/demo.py`. El script les vuelve a poner el hash de relleno de la semilla y les quita el secreto TOTP en cada `up`. Así, aunque el volumen de la base ya trajera la contraseña y el MFA públicos (por ejemplo el de una PC de desarrollo), esas cuentas dejan de entrar (comentario 10420 de RC-91). Una cuenta que ya no puede iniciar sesión (borrada, inactiva o de una empresa que no está activa) sale como 'cuenta de demo que no puede iniciar sesión, nada que apagar:'. Si no llega a la base, o si una cuenta que sí puede iniciar sesión no cambió, el servicio termina con error y la API, que lo espera, no arranca.

## Lo que fija el archivo del despliegue

Ningún .env le gana a estos valores:

- `DEMO_ACCOUNTS=false` y `DEMO_EXPLORER=false`.
- `COOKIE_SECURE=true`, porque el despliegue siempre va con HTTPS.
- `FORWARDED_ALLOW_IPS` con las IP fijas del portal (10.249.91.10) y de cloudflared (10.249.92.11). Cloudflare agrega la IP real al final de X-Forwarded-For y Next no le agrega nada si ya viene. uvicorn toma la primera IP de la derecha que no es de confianza. Una IP falsa que mande el navegador queda a la izquierda y no cuenta. El bloqueo por intentos del login cuenta por IPv4 y, como Cloudflare también entrega visitantes por IPv6, por red /64 en IPv6 (`cirdan/auth/sessions.py`): quien tiene un /64 puede estrenar dirección en cada intento, pero todas caen en el mismo contador. Quien tiene más de un /64 (un /56 trae 256 y un /48, 65 536) sí puede repartir los intentos entre sus redes /64 y saltarse el límite por IP, pero no el de 5 fallos por correo. Varios visitantes detrás de la misma IPv4 (una red corporativa) comparten contador.
- `UVICORN_TIMEOUT_KEEP_ALIVE=65`. El proxy de Next suelta una conexión ociosa con la API a los 5 s, lo mismo que uvicorn por omisión, y un POST que sale justo entonces termina en 500. Con 65 s la suelta siempre Next primero. Del lado del portal, la imagen de FrontKL pone `KEEP_ALIVE_TIMEOUT=95000`, por encima de los 90 s con que cloudflared reutiliza las conexiones.
- Sin `ports` en ningún servicio. Para entrar a la base de la VM se usa `docker compose exec db sh -c 'psql -U "$POSTGRES_USER" -d cirdan'`: `POSTGRES_USER` es la del contenedor, que sale del `.env` (`postgres` si no se puso).
- Rotación del registro de Docker en todos los servicios: 3 archivos de 10 MB.

Las redes `interna` (10.249.91.0/28) y `borde` (10.249.92.0/28) tienen subred fija, fuera de los rangos que Docker reparte solo (172.16.0.0/12 y 192.168.0.0/16) y de la VPC por omisión de AWS. Si otra red de la máquina ya usa esas subredes, `up` falla con un aviso de Docker. Las dos son `internal` (no salen a internet) e `isolated` (el host no tiene IP en ellas), así que un proceso de la VM no llega al portal sin pasar por el túnel. La API sí queda al alcance del host por su IP en la red `default`, pero ahí su X-Forwarded-For no cuenta: la API lo ve con la IP de la puerta de enlace de Docker. cloudflared sale a Cloudflare por su propia red, `salida`, que no comparte con nadie.

`portal` y `cloudflared` no llevan `container_name`: su nombre sale del proyecto. `db`, `valkey` y `api` siguen con los nombres fijos de `docker-compose.yml` (`cirdan-pg16`, `cirdan-valkey` y `cirdan-api`).

## Plan B

En una PC del equipo, la misma pila con un túnel propio (otro `TUNNEL_TOKEN`). Para pasar el tráfico se cambia en Cloudflare el destino de `lowtidesec.com` y `www.lowtidesec.com` al túnel del plan B. Al probarlo se anotan la fecha, los pasos y los minutos hasta que respondió lowtidesec.com (comentario 10383 de RC-91).

### Carpeta y volumen

El plan B no usa la base de desarrollo de esa PC: sus datos son de prueba y las cuentas reales de la VM no existen ahí.

1. En la carpeta de desarrollo, `docker compose down` (sin `-v`, la base de desarrollo se queda). Hace falta porque `cirdan-pg16`, `cirdan-valkey` y `cirdan-api` tienen nombre fijo y el plan B los volvería a crear.
2. Un clon aparte de BackKL y FrontKL, por ejemplo en `C:\lowtide-planb\BackKL` y `C:\lowtide-planb\FrontKL`, en el mismo commit que la VM. En la VM, `git -C BackKL rev-parse HEAD` y `git -C FrontKL rev-parse HEAD` dan los dos commits, y en cada clon del plan B `git checkout <commit>` los fija. Con otro commit el portal o la API pueden esperar otra versión de la base que la del respaldo de la VM.
3. Su `.env` como el de la VM (paso 2 de 'Antes de levantar'), con el `TUNNEL_TOKEN` del plan B, el mismo `TOTP_ENCRYPTION_KEY` de la VM y además `COMPOSE_PROJECT_NAME=lowtide-planb` (viene comentada en `.env.example`). Con otra llave TOTP los secretos de las cuentas reales no se descifran y nadie pasa la verificación en dos pasos. Sin `COMPOSE_PROJECT_NAME`, el proyecto toma el nombre de la carpeta: `C:\lowtide-planb\BackKL` da `backkl`, el mismo que la carpeta de desarrollo, y los dos usan el mismo volumen de la base, así que el `pg_restore --clean` y el `down -v` de abajo borrarían la base de desarrollo. Las contraseñas de PostgreSQL y Valkey pueden ser otras.
4. La primera línea de `docker compose config` tiene que ser `name: lowtide-planb`. Después, `docker compose up -d --build` y la comprobación de `logs demo-accounts`.
5. `docker volume ls` muestra `lowtide-planb_cirdan-pg16-data`, el volumen nuevo y vacío del plan B, aparte del de desarrollo (`backkl_cirdan-pg16-data` o el nombre de esa carpeta).

### Copiar los datos de la VM

Los comandos con `<` y `>` se corren en la VM o, en Windows, en Git Bash. En PowerShell 5.1, `>` escribe el respaldo en UTF-16 y lo deja inservible, y `<` no existe. `POSTGRES_USER` va entre comillas simples para que la tome el contenedor de la base, con el valor de su `.env` (`postgres` si no se puso).

Con el último respaldo de la VM, o uno nuevo hecho en la VM con:

```bash
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -Fc cirdan' > cirdan_vm.dump
```

En el plan B, con la API detenida para que nadie escriba a la mitad:

```bash
docker compose stop api
docker compose exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d cirdan --clean --if-exists --single-transaction' < cirdan_vm.dump
docker compose start api
```

`--clean --if-exists` borra lo que sembró la carga inicial y deja lo de la VM. El rol `cirdan_app` y su contraseña no van en el respaldo: los crea la carga inicial del plan B con su propio `.env`. Las sesiones no se copian, porque viven en Valkey: cada usuario vuelve a entrar.

### Volver a la VM

Lo que se escriba durante el plan B (escaneos, usuarios, cambios de contraseña) solo existe en el plan B. Antes de regresar el tráfico se copia de vuelta, también en Git Bash:

1. En el plan B, `docker compose stop api`, para que nada escriba después del respaldo. Desde aquí lowtidesec.com responde con error en `/api/v1` hasta el paso 4.
2. En el plan B, `docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -Fc cirdan' > cirdan_planb.dump`.
3. En la VM, `docker compose stop api`, el `pg_restore` de arriba con `cirdan_planb.dump` y `docker compose start api`.
4. En Cloudflare, el destino de los dos nombres vuelve al túnel de la VM.

Si el plan B dura poco y no se copia de vuelta, se avisa a los usuarios que lo que hagan ahí se pierde.

Al terminar, en la carpeta del plan B, `docker volume ls` confirma que el volumen es `lowtide-planb_cirdan-pg16-data` y luego `docker compose down -v` lo borra, porque trae los datos reales. En la carpeta de desarrollo, `docker compose up -d` levanta otra vez la pila local con su base de siempre.

## Pruebas

`python -m unittest pruebas/test_despliegue.py` arma la config con valores falsos y revisa todo lo de arriba, sin crear nada. El CI la corre con las pruebas sin base ni red. `pruebas/test_demo_cuentas.py` revisa que el script de demo apague las cuentas y `pruebas/test_bloqueo_ip.py` el contador por /64, las dos dentro del contenedor.

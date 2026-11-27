# Despliegue de LowTide (#49, RC-91)

La VM y el plan B levantan la misma pila: `docker-compose.yml` más `docker-compose.despliegue.yml`. El segundo archivo suma el portal (FrontKL) y Cloudflare Tunnel. Ningún puerto queda publicado en el host, ni siquiera en 127.0.0.1. Lo que entra por lowtidesec.com llega por el túnel al portal, y el portal reenvía `/api/v1` a la API. La API no tiene nombre público.

```
navegador → Cloudflare (HTTPS) → cloudflared ─borde─ portal ─interna─ api ─default─ db, valkey
                                      └─salida─ Cloudflare
```

Una VM equivalente también se crea y se borra desde código con Terraform, en su propio grupo de recursos y sin túnel por omisión: `docs/terraform.md` (#81, RC-132).

## Antes de levantar

**Alta de dominios:** el compose de despliegue la deja apagada mientras el `.env` no traiga `CARTA_ALTA_ENABLED=true`, y
eso se pone solo después de una restauración completa validada (sección 'Restaurar'). El respaldo diario incluye, en un solo paquete cifrado,
la base, el volumen con las cartas cifradas y la llave de cartas; la restauración completa verifica la llave y cada
documento referenciado antes de usar los destinos nuevos. El respaldo usa la retención actual de Azure: inmutabilidad
de 7 días y borrado entre 30 y 32 días. En la VM, la llave de cartas va como URL versionada de Key Vault
en `CARTA_KEY_VAULT_SECRET_URL`. Sin ninguna llave de cartas, el alta da error y el respaldo diario guarda solo la base
en el formato antiguo `.dump.age`. La verificación TXT de dominios ya registrados sigue
funcionando para los que estén en `DOMINIOS_EN_VIVO`.

Para pruebas locales sin datos reales: monta el volumen mediante `docker compose`, pon `CARTA_ALTA_ENABLED=true` y
una llave aleatoria `CARTA_ENCRYPTION_KEY` de 32 bytes en base64 url-safe, diferente de las del MFA y contraseñas.
El directorio del contenedor es `/var/lib/cirdan/cartas`, privado del usuario de la API. Fuera de Docker se debe
configurar `CARTA_STORAGE_DIR` con un directorio absoluto, privado y persistente. Como alternativa a la llave directa,
`CARTA_KEY_VAULT_SECRET_URL` acepta una URL versionada de Azure Key Vault; nunca se configuran ambas. La llave original
se conserva como secreto versionado y cada respaldo completo lleva una copia cifrada con age para recuperar la bóveda.
No se debe rotar ni borrar una versión mientras existan cartas cifradas con ella. El PDF se cifra con AES-256-GCM y la base guarda su SHA-256
y nombre opaco, no la carta en claro. La API comprueba la estructura básica del PDF, no su firma: el administrador
confirma que la carta firmada autoriza el dominio. Si una transacción falla después de escribir el archivo puede quedar
un archivo cifrado huérfano; no se borra automáticamente porque el resultado de una confirmación fallida puede ser
incierto. No se debe borrar ninguno sin conciliarlo primero con `domain_authorizations.signed_document_key` de todas las
empresas y con los respaldos.

1. FrontKL clonado junto a BackKL (`../FrontKL`), o su ruta en `PORTAL_DIR`.
2. `.env` copiado de `.env.example`, con contraseñas propias y además:
   - `ALLOWED_ORIGINS=https://lowtidesec.com,https://www.lowtidesec.com`. Van los dos porque el túnel publica los dos nombres y el navegador manda el Origin del nombre que abrió: sin el de www, la API responde 403 al login que llega por www. Sin la variable la pila no arranca. También apaga las cuentas de demo (RC-287).
   - `COOKIE_SECURE=true`. El archivo del despliegue ya la fija, pero con un origen https en `ALLOWED_ORIGINS` y sin `COOKIE_SECURE=true` la API no arranca (RC-286): así un `docker compose up` que se olvide de `docker-compose.despliegue.yml` tampoco publica la cookie de sesión sin Secure. Vale igual en el plan B y en el plan B de pruebas.
   - `TUNNEL_TOKEN`, el token del túnel de Cloudflare. Sin él la pila no arranca. Nunca va en git.
   - `COMPOSE_FILE=docker-compose.yml:docker-compose.despliegue.yml` y `COMPOSE_PATH_SEPARATOR=:`. Con eso cualquier `docker compose` de esa carpeta usa los dos archivos, aunque se escriba sin los `-f`. Sin ellos, un `docker compose up -d --build` recrea la API con la config de desarrollo, sin la red interna, y lowtidesec.com responde 500 en `/api/v1`. `COMPOSE_PATH_SEPARATOR=:` hace falta en Windows (plan B), donde el separador por omisión es `;`. En Linux no estorba.
   - `DOMINIOS_EN_VIVO` y `ORGS_GITHUB_DECLARADAS` según las cartas vigentes. Mientras la llave de Have I Been Pwned sea Core 1, ningún dominio de un tercero entra en `DOMINIOS_EN_VIVO`, aunque su carta esté vigente (sección 5.8, punto 7, de la [política de seguridad y privacidad](politica_seguridad_privacidad.md)).
   - `COMPOSE_PROFILES=programador`, solo después de aplicar la migración 030 (sección 'Escaneos programados').
   - La llave del MFA. En la VM va `TOTP_KEY_VAULT_SECRET_URL` y no va `TOTP_ENCRYPTION_KEY` (sección 'Llave del MFA en Azure Key Vault'). En el plan B es al revés (paso 3 de 'Carpeta y volumen'). Con las dos puestas, o con ninguna, la API no arranca.
   - La llave de las huellas de contraseña, con la misma regla: en la VM `PASSWORD_HASH_KEY_VAULT_SECRET_URL` y no `PASSWORD_HASH_ENCRYPTION_KEY`, y en el plan B al revés (sección 'Llave de las huellas de contraseña').
   - `CARTA_KEY_VAULT_SECRET_URL`, con versión, para la llave de las cartas. En producción no pongas `CARTA_ENCRYPTION_KEY`; la API pide la llave con la identidad administrada y el respaldo guarda una copia protegida con age.
   - `VALKEY_ADMIN_PASSWORD`, la contraseña de `cirdan_admin` en Valkey, distinta de `VALKEY_PASSWORD` (sección 'Usuarios de Valkey'). Sin ella ningún `docker compose` de esa carpeta corre.
   - `PWNED_PASSWORDS_ENABLED` vacía, como viene en `.env.example`, o en `true`. Así `docker-compose.despliegue.yml` prende la revisión de contraseñas filtradas (RC-334). Con `false` queda apagada y solo se revisa la lista local.
3. En Cloudflare:
   - Zero Trust: el túnel publica `lowtidesec.com` y `www.lowtidesec.com` hacia `http://portal:3000`.
   - SSL/TLS > Edge Certificates: 'Always Use HTTPS' prendido. Sin él el portal también responde por `http://` y el formulario de login manda la contraseña sin cifrar hasta Cloudflare (la API la rechaza después por el Origin, pero ya viajó). Se comprueba con `curl -sI http://lowtidesec.com/login` y `curl -sI http://www.lowtidesec.com/login`: los dos responden 301 con `Location: https://...`. HSTS queda para RC-89.
   - SSL/TLS > Edge Certificates: 'Minimum TLS Version' en **TLS 1.2** (ASVS 5.0 V12.1.1, #75). Con el valor por omisión, Cloudflare todavía acepta TLS 1.0 y 1.1. Se comprueba con `openssl s_client -connect lowtidesec.com:443 -servername lowtidesec.com -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0'`, que debe fallar el saludo, y con `-tls1_2` y `-tls1_3`, que deben conectar. `@SECLEVEL=0` hace falta porque el OpenSSL local ya no ofrece TLS 1.1 por su cuenta: sin él falla siempre y no prueba nada.
4. `docker login` con `DOCKERHUB_USERNAME` y `DOCKERHUB_TOKEN` de la cuenta 'lowtidesec' (solo lectura).
5. Docker Engine reciente, con Compose 2.24 o más nuevo. Las redes `borde` e `interna` usan `gateway_mode_ipv4=isolated` y los puertos se quitan con `ports: !reset []`. Un Docker viejo rechaza la opción de red y `up` falla: nunca levanta la pila sin el aislamiento. Se probó con Docker Engine 29.8 y Compose 5.5.

## Levantar

Con `COMPOSE_FILE` en el `.env` (paso 2), desde la carpeta de BackKL:

```bash
docker compose up -d --build
docker compose logs demo-accounts
```

La segunda línea tiene que decir 'DEMO_ACCOUNTS no es true: se apagan las cuentas de demo.' y luego 'cuenta de demo apagada:' con cada una de las 5 cuentas de `CUENTAS` de `cirdan/auth/demo.py`. El script les vuelve a poner el hash de relleno de la semilla y les quita el secreto TOTP en cada `up`. Así, aunque el volumen de la base ya trajera la contraseña y el MFA públicos (por ejemplo el de una PC de desarrollo), esas cuentas dejan de entrar (comentario 10420 de RC-91). Una cuenta inactiva o de una empresa que no está activa también sale 'apagada', porque el cambio va por su id. Si no hay fila con ese id en esa empresa (borrada o con otro id), sale 'cuenta de demo que no puede iniciar sesión, nada que apagar:' cuando ese correo no puede iniciar sesión, y 'cuenta de demo con otro id y sin la contraseña de demo, no se toca:' cuando puede, pero no con la contraseña pública. Si no llega a la base, o si ese correo todavía entra con la contraseña pública, el servicio termina con error y la API, que lo espera, no arranca. Lo mismo pasa si esa otra fila trae una huella cifrada (`lt1$`) y la llave de las huellas está en Key Vault, porque demo-accounts no llega a IMDS: el error dice 'No se revisó si entran con la contraseña pública' y nombra los correos. Se arregla con esa fila de la base: desactivarla (`is_active = false`) o cambiarle el correo a uno que no esté en `CUENTAS`, y volver a correr `up`.

## Usuarios de Valkey (RC-292)

Valkey ya no tiene una sola contraseña para todos. `docker-compose.yml` arranca `valkey-server` con tres usuarios:

- `default` apagado: sin usuario y contraseña nadie entra.
- `cirdan_api`, con `VALKEY_PASSWORD`. Es el de la API (`VALKEY_URL`) y del healthcheck. Solo corre los comandos de `cirdan/auth/sessions.py` y solo sobre sus prefijos de llave (`sess:`, `mfa:`, `login:` y los demás), también dentro de sus EVAL, sin pub/sub. CONFIG, MODULE, DEBUG, FLUSHALL, KEYS, SCAN y ACL le dan NOPERM. Un comando o un prefijo nuevo en `sessions.py` va también en la lista del compose: `pruebas/test_valkey_acl.py` falla si no.
- `cirdan_admin`, con `VALKEY_ADMIN_PASSWORD`, con todos los comandos, para operar a mano y para las pruebas. Esa variable solo llega al contenedor de Valkey: ni la API, ni el programador, ni demo-accounts la reciben.

Para entrar a mano: `docker exec -it cirdan-valkey sh -c 'valkey-cli --user cirdan_admin -a "$VALKEY_ADMIN_PASSWORD" --no-auth-warning'`. La contraseña la lee el shell del contenedor y no queda en la línea de comandos de la VM.

### Pasar la VM y las PC de desarrollo (una vez)

`${VALKEY_ADMIN_PASSWORD:?}` hace que cualquier `docker compose` de esa carpeta falle hasta que el `.env` la traiga, también `ps` y `logs`. El cambio del `command` recrea `cirdan-valkey`, y Valkey no guarda nada en disco (`--save ""`, `--appendonly no`): se pierden todas las sesiones, los MFA pendientes, los enlaces y restablecimientos sin usar y los bloqueos por intentos fallidos. Todos vuelven a entrar. Por eso va con el OK de quien administra la VM y fuera de una demo.

1. (VM) Respaldo del `.env` como en los demás pasos (`install -m 600`), y agregar `VALKEY_ADMIN_PASSWORD` con un valor nuevo al azar, sin que pase por la línea de comandos ni por el historial: `umask 077; python3 -c "import secrets;print('VALKEY_ADMIN_PASSWORD=' + secrets.token_urlsafe(24))" >> .env` y `stat -c %a .env` da 600. Se guarda en el gestor de contraseñas ('LowTide vm-lowtide VALKEY_ADMIN_PASSWORD').
2. (VM) `git pull` con `umask 022` y `docker compose --dry-run up -d --build`. Tiene que recrear `cirdan-valkey` y la API, y no `cirdan-pg16`. Si sale `cirdan-pg16`, no se sigue.
3. (VM) `docker compose up -d --build`. `docker compose ps` da `healthy` en `cirdan-valkey` y en la API, y una cuenta real entra con contraseña y MFA.
4. (VM) Comprobar: `docker exec cirdan-valkey sh -c 'valkey-cli --user cirdan_api -a "$VALKEY_PASSWORD" --no-auth-warning CONFIG GET maxmemory'` da NOPERM, `docker exec cirdan-valkey valkey-cli PING` da NOAUTH, y `docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' cirdan-api | grep -c '^VALKEY_ADMIN_PASSWORD='` da 0.

En una PC de desarrollo es lo mismo en su `.env`, y `docker compose up -d` recrea `cirdan-valkey` (las sesiones locales se pierden). El plan B y el plan B de pruebas también la necesitan en su `.env` (paso 3 de 'Carpeta y volumen').

Para regresar, se vuelve al commit anterior (`git checkout` del commit de antes) y se repite el paso 3: `--requirepass` con `VALKEY_PASSWORD` y `VALKEY_URL` sin usuario. `VALKEY_ADMIN_PASSWORD` puede quedarse en el `.env`, nadie la lee. Se vuelven a perder las sesiones.

## Lo que fija el archivo del despliegue

Ningún .env le gana a estos valores:

- `DEMO_ACCOUNTS=false` y `DEMO_EXPLORER=false`. El compose del despliegue también fija `API_DOCS=false`, así que `/openapi.json`, `/docs` y `/redoc` no existen, y la imagen corre uvicorn con `--no-server-header` (comentario 10063 de RC-91).
- `COOKIE_SECURE=true`, porque el despliegue siempre va con HTTPS. La respuesta del login trae `Set-Cookie: lt_session` con `Secure` (RC-286).
- `FORWARDED_ALLOW_IPS` con las IP fijas del portal (10.249.91.10) y de cloudflared (10.249.92.11). Cloudflare agrega la IP real al final de X-Forwarded-For y Next no le agrega nada si ya viene. uvicorn toma la primera IP de la derecha que no es de confianza. Una IP falsa que mande el navegador queda a la izquierda y no cuenta. El bloqueo por intentos del login cuenta por IPv4 y, como Cloudflare también entrega visitantes por IPv6, por red /64 en IPv6 (`cirdan/auth/sessions.py`): quien tiene un /64 puede estrenar dirección en cada intento, pero todas caen en el mismo contador. Quien tiene más de un /64 (un /56 trae 256 y un /48, 65 536) sí puede repartir los intentos entre sus redes /64 y saltarse el límite por IP, pero no el de 5 fallos por correo. Varios visitantes detrás de la misma IPv4 (una red corporativa) comparten contador.
- `UVICORN_TIMEOUT_KEEP_ALIVE=65`. El proxy de Next suelta una conexión ociosa con la API a los 5 s, lo mismo que uvicorn por omisión, y un POST que sale justo entonces termina en 500. Con 65 s la suelta siempre Next primero. Del lado del portal, la imagen de FrontKL pone `KEEP_ALIVE_TIMEOUT=95000`, por encima de los 90 s con que cloudflared reutiliza las conexiones.
- Sin `ports` en ningún servicio. Para entrar a la base de la VM se usa `docker compose exec db sh -c 'psql -U "$POSTGRES_USER" -d cirdan'`: `POSTGRES_USER` es la del contenedor, que sale del `.env` (`postgres` si no se puso).
- Rotación del registro de Docker en todos los servicios: 3 archivos de 10 MB.

Las redes `interna` (10.249.91.0/28), `borde` (10.249.92.0/28) y `default` (10.249.93.0/27, para la regla de IMDS de 'Solo la API llega a IMDS') tienen subred fija, fuera de los rangos que Docker reparte solo (172.16.0.0/12 y 192.168.0.0/16) y de la VPC por omisión de AWS. Si otra red de la máquina ya usa esas subredes, `up` falla con un aviso de Docker. `interna` y `borde` son `internal` (no salen a internet) e `isolated` (el host no tiene IP en ellas), así que un proceso de la VM no llega al portal sin pasar por el túnel. La API sí queda al alcance del host por su IP en la red `default`, pero ahí su X-Forwarded-For no cuenta: la API lo ve con la IP de la puerta de enlace de Docker. `default` no es ninguna de las dos: sale a internet y el host tiene IP en ella. cloudflared sale a Cloudflare por su propia red, `salida`, que no comparte con nadie.

La API tiene IP fija en `default` (10.249.93.20). Por eso en la VM los comandos de la API van con `docker compose exec api`, no con `docker compose run --rm api` como en el README: `run` pide la misma IP y, con la API arriba, falla con 'Address already in use'.

`portal` y `cloudflared` no llevan `container_name`: su nombre sale del proyecto. `db`, `valkey` y `api` siguen con los nombres fijos de `docker-compose.yml` (`cirdan-pg16`, `cirdan-valkey` y `cirdan-api`).

## Llave del MFA en Azure Key Vault

`TOTP_ENCRYPTION_KEY` cifra los secretos TOTP de todas las cuentas. En la VM no vive en el `.env`: vive en un secreto de Azure Key Vault y la API lo lee al arrancar con la identidad administrada de vm-lowtide (`cirdan/auth/keyvault.py`). El `.env` solo trae la URL del secreto en `TOTP_KEY_VAULT_SECRET_URL`.

- Desde la migración la llave no se escribe en el disco de la VM ni aparece en `docker inspect`, que sí muestra las variables de entorno: queda solo en la memoria del proceso. La migración no la cambia, así que los respaldos y snapshots de la VM de antes, los bloques del `.env` borrado y cualquier copia vieja del `.env` la siguen trayendo mientras no se rote. La copia del gestor de contraseñas también.
- La API pide el token al servicio de metadatos de Azure (169.254.169.254), sin proxy. Solo manda el token a una URL `https://<bóveda>.vault.azure.net/secrets/<nombre>/<versión>` y no sigue redirecciones.
- La URL lleva la versión del secreto, y la API no acepta una sin versión. Así cargar otro valor en la bóveda, por error o pensando que es una rotación, no cambia la llave que lee la API en el siguiente reinicio: hace falta editar el `.env`. La API solo revisa que la llave mida 32 bytes, no que descifre los secretos de la base. Con otra llave arranca `healthy` y nadie pasa la verificación en dos pasos: `/mfa/verify` responde 401 con 'Habla con el Admin.', cuenta un fallo y deja `auth.mfa_failed` con `reason: key` en la bitácora (RC-295).
- Si Key Vault o la identidad fallan, la API no arranca y `docker compose logs api` dice por qué (HTTP 403 es que falta el rol y HTTP 404, que el nombre o la versión de la URL no existen, y ese no se reintenta). Ningún mensaje lleva el token ni la llave. Cada lectura reintenta hasta 90 s en total, para aguantar un IMDS que se está actualizando, y el HEALTHCHECK del Dockerfile le da 200 s antes de contar fallos, porque con la llave de las huellas también en Key Vault (RC-330) son dos lecturas seguidas, cada una con sus 90 s. Si se rinde, uvicorn sale y `restart: unless-stopped` la vuelve a levantar.
- Lo que no cambia: quien sea root en la VM puede pedir el mismo token. Un contenedor que no sea la API no puede, por la regla de 'Solo la API llega a IMDS'. Lo que se gana es que cada lectura queda en el registro de la bóveda y que quitar el rol corta el acceso.
- Costo: Key Vault Standard cobra 0.03 USD por cada 10 mil operaciones, sin cuota por bóveda. Por cada llave en Key Vault la API hace dos peticiones por arranque, una a la identidad y otra a la bóveda, y solo la de la bóveda cuenta como operación. Con la del MFA y la de las huellas son cuatro peticiones y dos operaciones.

## Llave de las cartas en Azure Key Vault (RC-339)

En producción, crea una llave aleatoria distinta de las del MFA y de las huellas, guárdala como secreto y dale a la identidad administrada de la VM `Key Vault Secrets User` sobre ese secreto. La URL versionada que devuelve el comando va en `CARTA_KEY_VAULT_SECRET_URL`; el valor no va en `.env`:

```bash
umask 077
llave=$(mktemp /dev/shm/carta-key.XXXXXX)
python3 -c 'import base64,secrets,sys; sys.stdout.write(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())' > "$llave"
az keyvault secret set --vault-name <boveda> --name carta-encryption-key --file "$llave" --query id -o tsv
rm -f -- "$llave"
```

Guarda la llave en el gestor de contraseñas además de Key Vault. No crees una versión nueva ni borres la actual mientras haya cartas cifradas con ella: la URL fijada en el `.env` no cambia sola, y la restauración completa crea una nueva versión de la misma llave. La privada de age debe estar disponible en el procedimiento de recuperación del equipo; se necesita para abrir los paquetes, incluso si Key Vault no está disponible.

### Solo la API llega a IMDS

Cualquier contenedor con salida a internet llega a 169.254.169.254 y, en cuanto la VM tiene identidad, puede pedir su token y leer la llave: cloudflared, que es una imagen de terceros expuesta al túnel, por la red `salida`, y la base, Valkey y demo-accounts por `default`. Una regla en `DOCKER-USER`, la cadena de iptables que Docker deja para reglas propias y no borra, tira todo lo que va de un contenedor a 169.254.169.254, salvo lo que sale de la IP fija de la API (10.249.93.20, red `default` de `docker-compose.despliegue.yml`). Ningún otro contenedor puede recibir esa IP: Docker reparte solo 10.249.93.0/28. La base, Valkey y demo-accounts van sin `NET_RAW` (`cap_drop`), así que tampoco pueden quitársela a la API envenenando el ARP de `default`. Lo que corre en el host no pasa por esa cadena y la base, Valkey, demo-accounts y cloudflared no usan IMDS.

Va como servicio de systemd, para que quede puesta antes de que Docker levante los contenedores en cada arranque de la VM. `RequiredBy=docker.service` hace que Docker no arranque si la regla no se pudo poner, en vez de arrancar sin ella. `PartOf=docker.service` la vuelve a poner cada vez que se reinicia Docker. Al revés también: detener `lowtide-imds` detiene Docker.

```bash
sudo tee /etc/systemd/system/lowtide-imds.service >/dev/null <<'EOF'
[Unit]
Description=Solo la API de LowTide llega a IMDS (BackKL docs/despliegue.md)
Before=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -N DOCKER-USER 2>/dev/null; iptables -C DOCKER-USER -d 169.254.169.254/32 ! -s 10.249.93.20/32 -j DROP 2>/dev/null || iptables -I DOCKER-USER -d 169.254.169.254/32 ! -s 10.249.93.20/32 -j DROP'

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now lowtide-imds.service
systemctl list-dependencies docker.service | grep lowtide-imds
sudo iptables -S DOCKER-USER
```

`list-dependencies` muestra `lowtide-imds.service` entre las dependencias de Docker. `iptables -S DOCKER-USER` muestra la regla `-A DOCKER-USER ! -s 10.249.93.20/32 -d 169.254.169.254/32 -j DROP` antes que cualquier otra. Algo que vacíe las reglas sin reiniciar Docker (un `iptables-restore` o firewalld) la quita y systemd no se entera, así que `iptables -S DOCKER-USER` se repite en el paso 11 y después de cada actualización de la VM o de Docker. Docker usa iptables por omisión. Si `/etc/docker/daemon.json` trae `"firewall-backend": "nftables"`, la cadena no existe y esta regla no protege nada.

Comprobación, con la pila arriba: desde la API, el paso 8 de abajo lee el secreto. Desde otro contenedor de la misma red, esto tiene que fallar por tiempo (`TimeoutError` o `URLError`), no responder:

```bash
docker run --rm --network "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' cirdan-api)_default" --entrypoint python "$(docker inspect -f '{{.Config.Image}}' cirdan-api)" -c "import urllib.request; urllib.request.urlopen(urllib.request.Request('http://169.254.169.254/metadata/instance?api-version=2021-02-01', headers={'Metadata': 'true'}), timeout=5)"
```

### Armarla y pasar la VM (una vez)

Los pasos marcados (Azure) van en la terminal de quien administra Azure y los marcados (VM), en la carpeta de BackKL de la VM. La API sigue leyendo la llave del `.env` hasta el paso 10. La llave nunca va en un archivo ni en los argumentos de un comando: la lista de procesos, el evento 4688 de Windows y un EDR guardan esos argumentos.

1. (Azure) Bóveda en `rg-lowtide`, en la región de la VM, con permisos por RBAC: `az keyvault create -g rg-lowtide -n <bóveda> -l <región> --enable-rbac-authorization true`. El borrado suave viene prendido (90 días). La protección contra purga (`--enable-purge-protection true`) ya no se puede apagar después: se decide aparte.
2. (Azure) Quien carga el secreto necesita el rol 'Key Vault Secrets Officer' sobre la bóveda.
3. (Azure) Cargar el secreto `totp-encryption-key` con el valor que hoy tiene la VM, desde PowerShell y con la copia del gestor de contraseñas. `Invoke-RestMethod` corre dentro de PowerShell, así que la llave no pasa como argumento a otro proceso. La primera línea hace falta en PowerShell 5.1, que si no puede intentar con un TLS viejo.

   ```powershell
   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
   $v = bw get password 'LowTide vm-lowtide TOTP_ENCRYPTION_KEY'
   $t = az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv
   $r = Invoke-RestMethod -Method Put -Uri 'https://<bóveda>.vault.azure.net/secrets/totp-encryption-key?api-version=7.4' -Headers @{Authorization = "Bearer $t"} -ContentType 'application/json' -Body (@{value = $v} | ConvertTo-Json)
   $r.id
   Remove-Variable v, t, r
   ```

   `$r.id` es la URL del secreto con su versión, `https://<bóveda>.vault.azure.net/secrets/totp-encryption-key/<versión>`. Esa URL es la que va en los pasos 8 y 9.
4. (VM) Desplegar este commit con el `.env` de siempre, todavía con `TOTP_ENCRYPTION_KEY`: `git pull`, `docker compose --dry-run up -d --build` y `docker compose up -d --build`. La imagen trae `cirdan/auth/keyvault.py` y la red `default` pasa a 10.249.93.0/27, así que Compose recrea esa red y todos los contenedores. El volumen de la base se queda. Valkey no guarda nada en disco: se pierden las sesiones y cada usuario vuelve a entrar. Al final `docker compose ps` dice `healthy` y `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' cirdan-api` muestra 10.249.93.20. Sin este paso el 8 falla con `ModuleNotFoundError`.
5. (VM) La regla de 'Solo la API llega a IMDS', antes de que la VM tenga identidad.
6. (Azure) Identidad de la VM: `az vm identity assign -g rg-lowtide -n vm-lowtide`. Su `principalId` es el que recibe el rol.
7. (Azure) Solo lectura y solo de ese secreto: `az role assignment create --assignee-object-id <principalId> --assignee-principal-type ServicePrincipal --role 'Key Vault Secrets User' --scope <id de la bóveda>/secrets/totp-encryption-key`. El id sale de `az keyvault show -n <bóveda> --query id -o tsv`.
8. (VM) Comprobar que la API llega a la bóveda y que su valor es el mismo. Sin las dos cosas no se sigue: con otra llave ninguna cuenta pasa la verificación en dos pasos.

   ```bash
   docker compose exec api python -c "import hmac, os; from cirdan.auth import keyvault; v = keyvault.leer_secreto('<URL con versión del paso 3>'); print('igual' if hmac.compare_digest(v, os.environ['TOTP_ENCRYPTION_KEY']) else 'distinta')"
   ```

   Tiene que imprimir `igual`. Un 403 puede tardar unos minutos en irse después de asignar el rol. Después, la comprobación de 'Solo la API llega a IMDS' tiene que fallar por tiempo.
9. (VM) En el `.env`, agregar `TOTP_KEY_VAULT_SECRET_URL=<URL con versión del paso 3>` y borrar la línea de `TOTP_ENCRYPTION_KEY`.
10. (VM) `docker compose --dry-run up -d --build` para ver qué contenedores recrea y luego `docker compose up -d --build`, que recrea la API con el `.env` nuevo.
11. (VM) `docker compose ps api` dice `healthy`. Además, `docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' cirdan-api | grep -c '^TOTP_ENCRYPTION_KEY=.'` da 0, `sudo iptables -S DOCKER-USER` sigue mostrando la regla de IMDS y una cuenta real entra con contraseña y MFA.

Para regresar, se pone otra vez `TOTP_ENCRYPTION_KEY` en el `.env` con la copia del gestor de contraseñas, se borra `TOTP_KEY_VAULT_SECRET_URL` y se repite el paso 10. La copia del gestor se queda siempre: el plan B la usa y, sin ella o sin la bóveda, los secretos TOTP de la base ya no se descifran. Una versión nueva en la bóveda no se usa hasta que alguien cambie la URL del `.env`. Para rotar la llave, los pasos de abajo.

### Rotar la llave del MFA (RC-295)

Se rota si la llave se filtra o cuando se decida, siempre con el OK de quien administra la VM. Nadie vuelve a dar de alta su app autenticadora. Mientras se rota, la llave de antes va en `TOTP_PREVIOUS_KEY_VAULT_SECRET_URL` (en la VM) o en `TOTP_PREVIOUS_ENCRYPTION_KEY` (desarrollo y plan B), una de las dos. El secreto guardado no lleva versión: la API lo prueba con la actual y, si no abre, con la anterior. El que abre con la anterior se guarda cifrado con la actual en el mismo UPDATE que gasta el primer código bueno de esa cuenta, en `/mfa/verify` o al registrar una passkey. La API no arranca si la anterior es la misma llave que la actual, aunque una venga del `.env` y la otra de Key Vault, ni con las dos formas de la anterior puestas. Un secreto que no abre con ninguna da 401 con 'Habla con el Admin.' (400 al registrar una passkey, para que el portal no cierre la sesión), cuenta como fallo y deja `auth.mfa_failed` (o `auth.passkey_registration_failed`) con `reason: key` en la bitácora. Nunca 500. Un QR pedido antes de rotar sigue sirviendo con la anterior y se guarda con la actual.

Antes del paso 1 se cuenta una vez como en el paso 4 (sin la anterior puesta) y se anota el total de 'con ninguna': los pasos 4 y 5 lo comparan.

1. (Azure) Generar la llave nueva y guardarla en el gestor de contraseñas ('LowTide vm-lowtide TOTP_ENCRYPTION_KEY v2') como en el paso 3 de 'Armarla y pasar la VM', pero como un secreto nuevo, `totp-encryption-key-v2`, y darle a la identidad de la VM 'Key Vault Secrets User' sobre ese secreto como en el paso 7. Tiene que ser otra que la de las huellas y la de las cartas. El secreto de antes no se borra.
2. (VM) En el `.env`: `TOTP_PREVIOUS_KEY_VAULT_SECRET_URL=<la URL con versión que hoy está en TOTP_KEY_VAULT_SECRET_URL>` y `TOTP_KEY_VAULT_SECRET_URL=<el $r.id del secreto nuevo>`.
3. (VM) Reconstruir: `docker compose --dry-run up -d --build api` (sin recrear `cirdan-pg16` ni `cirdan-valkey`) y `docker compose up -d --build api`. `docker compose ps api` dice `healthy`. Un 403 en `docker compose logs api` es que falta el rol del paso 1.
4. (VM) Contar, sin cambiar nada, cuántos secretos siguen con la anterior. postgres da las empresas con MFA, porque la API entra con RLS y no las puede listar, y la API prueba cada secreto con las dos llaves:

   ```bash
   set -o pipefail; docker exec cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 -Atc "SELECT DISTINCT organization_id FROM users WHERE totp_secret_enc IS NOT NULL" | docker compose exec -T api python -m cirdan.auth.contar_totp; echo "salida $?"
   ```

   Imprime por empresa y en total cuántos abren con la actual, cuántos solo con la anterior, cuántos con ninguna y cuántos 'sin acceso'. Solo vale con `salida 0`: si el psql falla o no da ninguna empresa, el comando termina con error y no hay conteo. Solo lee: no bloquea filas ni escribe en la bitácora, y la salida no lleva secretos, correos ni ids de usuario. Cada cuenta que entra con su código pasa de 'con la anterior' a 'con la actual'. 'sin acceso' son cuentas inactivas o de una empresa fuera de trial y active: no entran, su secreto no se vuelve a cifrar y no cuentan para el paso 5. Justo después del paso 3, 'con ninguna' tiene que dar lo mismo que en el conteo de antes del paso 1. Si subió, la anterior no es la llave de antes (otra URL u otra versión): se corrige el paso 2 y se cuenta otra vez, sin seguir al paso 5. Las cuentas que no entran se quedan con la anterior: se les pide que entren una vez o se acepta que, al quitar la anterior, haya que restablecerles el MFA como se dice abajo.
5. (VM) Con `0 con la anterior` en el total y 'con ninguna' igual que en el conteo de antes del paso 1, quitar `TOTP_PREVIOUS_KEY_VAULT_SECRET_URL` del `.env` y reconstruir como en el paso 3. Después se puede quitar el rol de la identidad sobre el secreto de antes. El secreto de antes y su copia del gestor se quedan al menos 33 días después de este paso, porque los respaldos de antes de rotar ('Respaldo diario') traen secretos que solo abren con esa llave. Para restaurar uno, se vuelve a poner la anterior como en el paso 2, con su rol.

En desarrollo y en el plan B es lo mismo con `TOTP_PREVIOUS_ENCRYPTION_KEY` y `TOTP_ENCRYPTION_KEY`, sin Key Vault, y `docker compose exec -T api` como en la VM. Con `DEMO_ACCOUNTS=true` las cuentas de demo se vuelven a cifrar con la actual en cada arranque.

#### Restablecer el MFA de una cuenta

Una cuenta cuyo secreto no abre con ninguna llave (la llave se perdió, o se quitó la anterior con cuentas pendientes o 'sin acceso' que después se activaron) recibe 'Habla con el Admin.' en cada intento. El Admin de su empresa no lo puede arreglar desde el portal: avisa a quien administra la VM, que con el correo de la cuenta saca sus ids y la restablece. El comando solo lo hace si de verdad ninguna llave abre ese secreto, deja `auth.mfa_reset` en la bitácora y no toca las passkeys:

```bash
docker exec cirdan-pg16 psql -U postgres -d cirdan -Atc "SELECT organization_id, id FROM users WHERE email = '<correo>'"
docker compose exec -T api python -m cirdan.auth.restablecer_mfa <organization_id> <id>
docker compose exec -T api python -m cirdan.auth.restablecer_mfa <organization_id> <id> --si
```

El primero solo revisa y dice si la cuenta se puede restablecer. El segundo, con `--si`, borra su secreto TOTP. Después la cuenta activa otra vez su app autenticadora: un Admin en el mismo inicio de sesión, un operador por fuera como en su alta y las demás en su perfil. Si la cuenta llegó a 5 intentos, su correo sigue bloqueado hasta 15 minutos.

## Llave de las huellas de contraseña (RC-330)

La huella argon2id de cada contraseña se guarda cifrada con AES-256-GCM (`cirdan/auth/passwords.py`): `lt1$` más la cadena PHC cifrada, con el id del usuario como dato asociado. Con un volcado de la base, sin la llave, no se pueden probar contraseñas fuera de línea, y la huella de una cuenta copiada a otra no abre. La llave es otra que la del MFA: la API compara los bytes de las dos al arrancar y no arranca si son la misma, aunque una venga del `.env` y la otra de Key Vault, y tampoco acepta dos versiones del mismo secreto. Sigue la misma regla que la del MFA: en la VM, la URL de su secreto de Key Vault en `PASSWORD_HASH_KEY_VAULT_SECRET_URL`, y en desarrollo, el CI y el plan B, la llave misma en `PASSWORD_HASH_ENCRYPTION_KEY`. Una de las dos, y sin llave la API no arranca, igual que el script de demo.

- Las huellas de antes, sin cifrar, entran todavía y quedan cifradas en ese mismo inicio de sesión. No hace falta restablecer contraseñas. El hash de relleno de las semillas y de `cirdan/auth/demo.py` no cambia y sigue sin abrir nada.
- Si la llave se pierde, ninguna contraseña guardada vuelve a abrir y cada cuenta se restablece con su script de alta. Por eso la copia del gestor de contraseñas se queda siempre, como la del MFA.
- Si el cambio se revierte, el código viejo no abre las huellas cifradas: las cuentas que ya entraron se restablecen igual.
- Rotar la llave no pide contraseñas nuevas, porque se descifra la huella y se vuelve a cifrar (RC-333). El número de `lt1$` es la versión de la llave: los pasos están en 'Rotar la llave de las huellas'.

### Pasarla a la VM (una vez)

Cada paso va con el OK de quien administra la VM. La llave nunca va en un archivo ni en los argumentos de un comando, como en 'Llave del MFA en Azure Key Vault'.

1. (Azure) Generar la llave en PowerShell, guardar la copia en el gestor de contraseñas ('LowTide vm-lowtide PASSWORD_HASH_ENCRYPTION_KEY') pegándola del portapapeles, y cargarla como el secreto `password-hash-key` de la misma bóveda (rol 'Key Vault Secrets Officer'):

   ```powershell
   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
   $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
   $v = [Convert]::ToBase64String($b).Replace('+', '-').Replace('/', '_')
   Set-Clipboard -Value $v   # pegarla en el gestor y luego: Set-Clipboard -Value ' '
   $t = az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv
   $r = Invoke-RestMethod -Method Put -Uri 'https://<bóveda>.vault.azure.net/secrets/password-hash-key?api-version=7.4' -Headers @{Authorization = "Bearer $t"} -ContentType 'application/json' -Body (@{value = $v} | ConvertTo-Json)
   $r.id
   Remove-Variable b, v, t, r
   ```

2. (Azure) Lectura solo de ese secreto para la identidad de la VM: `az role assignment create --assignee-object-id <principalId> --assignee-principal-type ServicePrincipal --role 'Key Vault Secrets User' --scope <id de la bóveda>/secrets/password-hash-key`.
3. (VM) En el `.env`, agregar `PASSWORD_HASH_KEY_VAULT_SECRET_URL=<el $r.id del paso 1>`, sin `PASSWORD_HASH_ENCRYPTION_KEY`.
4. (VM) Desplegar este commit: `git pull`, `docker compose --dry-run up -d --build` y `docker compose up -d --build`. `docker compose ps api` dice `healthy`. Un 403 en `docker compose logs api` es que falta el rol del paso 2.
5. (VM) Cada cuenta real entra una vez con contraseña y MFA. Después, como postgres y solo lectura, esta consulta tiene que quedar vacía. Cuenta solo las cuentas que pueden iniciar sesión, las mismas que deja entrar `login_lookup()` (migración 004): una cuenta apagada o de una empresa que no está en `trial` ni `active` nunca entra y su huella vieja se queda sin cifrar hasta que se reactive y entre:

   ```bash
   docker exec cirdan-pg16 psql -U postgres -d cirdan -Atc "SELECT u.email FROM users u JOIN organizations o ON o.id = u.organization_id WHERE u.is_active AND o.status IN ('trial', 'active') AND u.password_hash NOT LIKE 'lt1\$%' AND u.password_hash <> '\$argon2id\$v=19\$m=65536,t=3,p=4\$ZGVtby1zYWx0\$ZGVtby1vbmx5'"
   ```

En el plan B la misma llave va en `PASSWORD_HASH_ENCRYPTION_KEY`, tomada del gestor o con `az keyvault secret show --id <URL con versión> --query value -o tsv`, y se borra del `.env` al terminar. Con otra llave ninguna contraseña de la VM abre.

### Rotar la llave de las huellas (RC-333)

Se rota si la llave se filtra o cuando se decida, siempre con el OK de quien administra la VM. Nadie cambia su contraseña. La versión de la llave va en el prefijo de cada huella (`lt1$`, `lt2$`...) y en `PASSWORD_HASH_KEY_VERSION`, que sin poner vale 1. Mientras se rota, la llave de antes va en `PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL` (en la VM) o en `PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY` (desarrollo y plan B), una de las dos. Con ella puesta, una huella de la versión anterior entra y el login la guarda cifrada con la actual. La API no arranca si la anterior es la misma llave que la actual o que la del MFA, ni con la anterior puesta y la versión en 1. Sin la anterior, una huella de la versión anterior no abre: 'Correo o contraseña incorrectos.' en el mismo tiempo que un correo que no existe.

Nunca se crea otra versión del secreto `password-hash-key` sin seguir estos pasos: con una URL sin versión, la API tomaría la nueva al reiniciarse y ninguna huella abriría. Por eso las URL del `.env` siempre llevan su versión.

1. (VM, una vez) La migración 026, que da al comando las empresas con huellas de una versión. La API no la lee: `docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/026_huellas_por_version.sql`.
2. (Azure) Generar la llave nueva y guardarla en el gestor de contraseñas ('LowTide vm-lowtide PASSWORD_HASH_ENCRYPTION_KEY v2') como en el paso 1 de 'Pasarla a la VM', pero como un secreto nuevo, `password-hash-key-v2`, y darle a la identidad de la VM 'Key Vault Secrets User' sobre ese secreto como en el paso 2. El secreto de antes no se borra.
3. (VM) En el `.env`: `PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL=<la URL con versión que hoy está en PASSWORD_HASH_KEY_VAULT_SECRET_URL>`, `PASSWORD_HASH_KEY_VAULT_SECRET_URL=<el $r.id del secreto nuevo>` y `PASSWORD_HASH_KEY_VERSION=2` (o la que sigue).
4. (VM) Reconstruir: `docker compose --dry-run up -d --build api` (sin recrear `cirdan-pg16`) y `docker compose up -d --build api`. `docker compose ps api` dice `healthy`. Un 403 en `docker compose logs api` es que falta el rol del paso 2.
5. (VM) Contar sin cambiar nada y luego cifrar: `docker compose exec api python -m cirdan.auth.rotar_huellas --prueba` y `docker compose exec api python -m cirdan.auth.rotar_huellas`. Imprime por empresa cuántas cambió, cuántas no abrieron y cuántas quedan de la versión anterior, y, por empresa con al menos una cambiada, deja un evento `auth.password_hash_rotated` con esos conteos en `audit_log`. Si se corta a media empresa (Ctrl+C o un error), antes de salir deja el evento de lo que ya cambió con `interrupted`, y si la base es la que falló lo dice en la salida. Ni la salida ni la bitácora llevan huellas. Correrlo otra vez no cambia nada ni escribe eventos. Una que no abre ya no abría con la llave de antes (otra llave o una huella dañada): esa cuenta se restablece con su script de alta.
6. (VM) Como postgres y solo lectura, con el número de la versión anterior. Tiene que dar `0`:

   ```bash
   docker exec cirdan-pg16 psql -U postgres -d cirdan -Atc "SELECT count(*) FROM users WHERE password_hash LIKE 'lt1\$%'"
   ```

7. (VM) Quitar `PASSWORD_HASH_PREVIOUS_KEY_VAULT_SECRET_URL` del `.env` y reconstruir como en el paso 4. `PASSWORD_HASH_KEY_VERSION` se queda. Después se puede quitar el rol de la identidad sobre el secreto de antes. El secreto de antes y su copia del gestor se quedan al menos 33 días después del paso 6: cada respaldo dura de 30 a 32 días ('Respaldo diario') y los de antes de rotar traen huellas de la versión anterior, que solo abren con esa llave. Para restaurar uno de ellos se le vuelve a dar a la identidad 'Key Vault Secrets User' sobre el secreto de antes, como en el paso 2 (sin ese rol la API recibe 403 y no arranca), y se vuelve a poner la anterior como en el paso 3.

En desarrollo y en el plan B es lo mismo con `PASSWORD_HASH_PREVIOUS_ENCRYPTION_KEY` y `PASSWORD_HASH_ENCRYPTION_KEY`, sin Key Vault, y `docker compose exec api` como en la VM.

## TOTP obligatorio para el Admin (RC-5)

El TOTP del Admin se revisa al crear la sesión, no en cada petición. Las sesiones de un Admin sin TOTP abiertas antes de desplegar RC-5 seguirían vivas hasta 8 h, así que se cierran al desplegar (H6 de la revisión de RC-5):

1. (VM) Después del `up -d --build`, listar los Admins activos sin TOTP: `docker exec cirdan-pg16 psql -U postgres -d cirdan -Atc "SELECT id FROM users WHERE role = 'admin' AND is_active AND (mfa_enabled_at IS NULL OR totp_secret_enc IS NULL)"`.
2. (VM) Por cada id, cerrar sus sesiones: `docker compose exec api python -c "from cirdan.auth import sessions; sessions.delete_others('<id>', None)"`. Sin filas en el paso 1 no hay nada que cerrar. En su siguiente `/login` reciben el 403 con el QR.

## Escaneos programados (RC-52)

El servicio `programador` vuelve a escanear cada dominio autorizado según el plan de su empresa (`plans.scan_interval`: Starter cada 7 días, Business y Enterprise cada día). Usa la misma imagen y el mismo rol de la base que la API, sin puertos y sin llegar a IMDS. Va con profile: sin `COMPOSE_PROFILES`, `docker compose up -d` no lo enciende. Al encenderlo salen en el acto los dominios con `next_scan_at` vacío o vencido, así que se enciende con el OK de quien administra la VM.

1. (VM, una vez) La migración 030, antes de encenderlo. La API no la lee: `docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/030_escaneos_programados.sql`.
2. (VM) Revisar que `DOMINIOS_EN_VIVO` del `.env` lista solo los dominios con carta vigente y, con la llave Core 1 de Have I Been Pwned, ninguno de un tercero (paso 2 de 'Antes de levantar'). El programador se salta los demás sin consultar su TXT y los vuelve a ver al día siguiente.
3. (VM) En el `.env`, `COMPOSE_PROFILES=programador`. Con ella cada `docker compose up -d --build` de esta guía, y `infra/verificar_imagenes.sh --levantar` con las imágenes firmadas, también recrea el programador con el código nuevo. Sin ella, un programador ya encendido seguiría con la imagen de antes, porque un `up` sin su profile no lo toca.
4. (VM) `docker compose --dry-run up -d --build` (sin recrear `cirdan-pg16`) y `docker compose up -d --build`. `docker compose ps programador` dice `running` y `docker compose logs programador` dice 'escaneo programado' con cada escaneo que pidió, sin errores.
5. Para apagarlo: quitar `COMPOSE_PROFILES` del `.env` y `docker compose --profile programador stop programador`. Tiene 60 s para cerrar: los escaneos que dejó corriendo quedan en 'failed' y su turno queda a una hora, no al siguiente intervalo del plan, así que salen en cuanto se vuelva a encender.

## Inteligencia de amenazas (RC-127)

El servicio `inteligencia` carga el catálogo completo CISA KEV y el archivo diario EPSS de FIRST en `cves`. Descarga el archivo público completo: no envía a FIRST ni a CISA los CVE que encontró en los clientes. Corre al arrancar y cada 24 horas; si falla, conserva la última carga y reintenta en una hora. Un candado de PostgreSQL evita que dos instancias actualicen a la vez. No cambia la severidad ni recalcula el score.

El servicio usa `cirdan_intel`, un rol separado que solo puede leer `cves` y actualizar las columnas de inteligencia. No puede leer hallazgos ni modificar CVSS. La API sigue usando `cirdan_app`, que no puede actualizar esas columnas.

1. Aplicar las migraciones pendientes hasta la 038, antes de encender el servicio. Para la 038:
   ```bash
   docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/038_inteligencia_amenazas.sql
   ```
2. Elegir una contraseña independiente, guardarla en `CIRDAN_INTEL_PASSWORD` del `.env` y establecer la misma para el rol, sin escribirla en el comando:
   ```bash
   docker compose exec db psql -U postgres -d cirdan
   ```
   Dentro de `psql`, ejecutar `\password cirdan_intel`, introducirla dos veces y salir con `\q`.
3. Agregar `inteligencia` a `COMPOSE_PROFILES`, conservando los perfiles existentes; por ejemplo, `COMPOSE_PROFILES=programador,inteligencia`. Reconstruir y levantar con los archivos de Compose habituales del despliegue.
4. Verificar `docker compose ps inteligencia` y `docker compose logs inteligencia`: debe aparecer `inteligencia actualizada` con los conteos de CVE, KEV y EPSS. Comprobar `SELECT count(*), max(intel_updated_at) FROM cves` como postgres. Vigilar el registro y la antigüedad de esa fecha: un contenedor en ejecución no demuestra que la última descarga haya funcionado.

La carga rechaza un catálogo KEV incompleto y un archivo EPSS inválido, con fecha futura o con más de tres días. Hasta una carga correcta, los CVE nuevos tienen KEV desconocido; si después falla una descarga, los valores anteriores pueden estar desactualizados. No rellena CVSS de NVD: esos datos los aportan los recolectores que ya lo consultan.

Para apagarlo, quitar `inteligencia` de `COMPOSE_PROFILES` y ejecutar `docker compose --profile inteligencia stop inteligencia`. Volver a encenderlo hace una carga inmediata.

## Retención de 12 meses (RC-257)

El servicio `retencion` borra cada día, empresa por empresa, lo que pasa de 12 meses: entregas y alertas, scores con sus aportes, hallazgos resueltos (con su brecha), activos sin verse ni hallazgos, reportes y escaneos que ya nadie referencia. No borra hallazgos abiertos, en riesgo aceptado ni falsos positivos, ni la bitácora, las cartas o las verificaciones del TXT (#140). Usa el rol `cirdan_retention`, sin superusuario ni BYPASSRLS, y cada corrida deja en la bitácora de cada empresa un evento `retention.purged` con cuántas filas borró por tabla.

1. Aplicar la migración 039 (después de la 038):
   ```bash
   docker exec -i cirdan-pg16 psql -U postgres -d cirdan -v ON_ERROR_STOP=1 < db/migraciones/039_rol_retencion.sql
   ```
2. Elegir una contraseña, guardarla en `CIRDAN_RETENTION_PASSWORD` del `.env` y ponerla al rol sin escribirla en el comando: `docker compose exec db psql -U postgres -d cirdan`, luego `\password cirdan_retention` y `\q`. En una base nueva la pone `db/init/cargar_cirdan.sh`.
3. Agregar `retencion` a `COMPOSE_PROFILES`, conservando los demás (por ejemplo `COMPOSE_PROFILES=programador,inteligencia,retencion`), y levantar con los archivos de Compose habituales.
4. Verificar `docker compose logs retencion` (debe decir `retención aplicada`) y, como postgres, `SELECT organization_id, occurred_at, details FROM audit_log WHERE action = 'retention.purged' ORDER BY occurred_at DESC LIMIT 5`.

Para una corrida a mano: `docker compose run --rm retencion python -m cirdan.retencion --una-vez`. Para apagarlo, quitar `retencion` de `COMPOSE_PROFILES` y `docker compose --profile retencion stop retencion`.

## Respaldo diario (RC-233, RC-28 y RC-339)

Una vez al día, a las 09:00 UTC (03:00 en Monterrey), `lowtide-respaldo.timer` corre `db/respaldo/respaldar.sh`:

1. Espera hasta 5 minutos a que `cirdan-pg16` acepte conexiones: si la VM estaba apagada a esa hora, el timer corre al arrancar, antes que la base.
2. Toma `pg_dump -Fc` como postgres (nunca `cirdan_app`, que con FORCE RLS no ve todas las filas), seguido del volumen de cartas y la llave activa que obtiene la API.
3. Cifra cada componente con age y agrupa únicamente esos archivos cifrados. Los temporales viven en `/run` (o `/run/lock` si `/run` no es escribible), siempre en tmpfs; ni el dump ni la llave de cartas en claro se escriben en disco persistente. El paquete completo se cifra de nuevo con age y una llave pública. La llave privada de recuperación no está en la VM: vive en el gestor de contraseñas y en los medios seguros de recuperación del equipo.
4. Deja `cirdan_<fecha UTC>_<8 hex al azar>.backup.age` en `/var/backups/lowtide` (carpeta 700, archivo 600). El sufijo al azar hace que nadie pueda ocupar antes en Azure el nombre del respaldo de mañana.
5. La base se captura primero. Como el archivo de carta se sincroniza antes de que su referencia se confirme en la base y las cartas son inmutables, esa secuencia puede incluir archivos huérfanos, pero no omite una carta que la base restaurada referencia. `restaurar_completo.sh` comprueba después que cada referencia abre con la llave restaurada y su SHA-256 coincide.
6. Sube el paquete a Azure Blob con la identidad administrada de la VM. No hay llave de almacenamiento en la VM: el token sale de IMDS y llega a `curl` por stdin. La subida nunca escribe encima de un blob con el mismo nombre (`If-None-Match: *`), Azure revisa el MD5 del archivo y el blob lleva su sha256 en `x-ms-meta-sha256`. Si `curl` reintenta una subida que sí llegó, Azure responde `403 UnauthorizedBlobOverwrite`, porque la identidad no puede escribir encima, y el respaldo cuenta como subido solo si el blob que ya está tiene el mismo MD5. En cada corrida también sube los respaldos locales que todavía no están en Azure, así que una subida que falló un día se repite al siguiente.
7. Conserva en la VM los respaldos de los últimos 7 días que tienen alguno (una corrida a mano no le quita su lugar a un día). Nunca borra uno que no está en Azure, salvo que ya haya más de 31. Los antiguos `.dump.age` se conservan y cargan como legado, pero contienen solo la base y no son puntos completos de recuperación.

El contenedor tiene una política de inmutabilidad de 7 días: nadie, ni con el rol de la VM, borra ni cambia un respaldo antes de ese plazo. Una regla del ciclo de vida lo borra después de 30 días, y como Azure la aplica una vez al día, cada blob dura entre 30 y 32 días. La regla borra por antigüedad, no por cantidad: si los respaldos dejan de llegar, el último bueno se borra a los 30 días, así que ese es el plazo para enterarse (ver la alerta de abajo). Valkey no se respalda: guarda sesiones, MFA pendientes y bloqueos, y no escribe a disco. El respaldo no lleva contraseñas de roles: en una base nueva los roles los crea `db/init`.

La identidad de la VM tiene en el contenedor un rol propio (`db/respaldo/rol_respaldo.json`) que solo crea blobs nuevos y los lee (`blobs/add/action` y `blobs/read`), sin borrar. La API también llega a IMDS (la llave del MFA), así que una API comprometida podría pedir ese mismo token: con el rol propio no puede borrar respaldos ni, por la inmutabilidad, cambiar los de los últimos 7 días, y con el sufijo al azar no bloquea la subida del día. El rol no lleva `blobs/write`, así que la VM tampoco puede sobrescribir un blob ni cambiarle el nivel de acceso. Además, con la retención por tiempo Azure nunca deja sobrescribir un blob, ni después de los 7 días: solo se puede borrar, y eso lo hace la regla del ciclo de vida. Lo que lea está cifrado con age.

Lo que no cubre: la cuenta de almacenamiento está en la misma suscripción que la VM. Si la suscripción se suspende (por ejemplo, al acabarse el crédito), se pierden las dos. Si el respaldo falla, `systemctl --failed` y `journalctl -u lowtide-respaldo` lo dicen, y sin la alerta de Azure Monitor nadie recibe aviso.

### Armarlo (una vez)

En Azure, desde una PC con `az login` y desde la raíz de BackKL (el nombre de la cuenta es un ejemplo y tiene que ser único en Azure):

```bash
az storage account create -g rg-lowtide -n stlowtiderespaldo -l westus2 --sku Standard_LRS --kind StorageV2 \
  --https-only true --min-tls-version TLS1_2 --allow-blob-public-access false --allow-shared-key-access false
az storage container-rm create -g rg-lowtide --storage-account stlowtiderespaldo -n respaldos --public-access off
az storage container immutability-policy create -g rg-lowtide --account-name stlowtiderespaldo -c respaldos --period 7
az storage account management-policy create -g rg-lowtide --account-name stlowtiderespaldo --policy @db/respaldo/ciclo_de_vida.json
rol=$(mktemp) && sed "s/SUSCRIPCION/$(az account show --query id -o tsv)/" db/respaldo/rol_respaldo.json > "$rol"
az role definition create --role-definition @"$rol" && rm -f "$rol"
az role assignment create --role 'LowTide respaldo: subir y leer blobs' \
  --assignee-object-id "$(az vm show -g rg-lowtide -n vm-lowtide --query identity.principalId -o tsv)" \
  --assignee-principal-type ServicePrincipal \
  --scope "$(az storage account show -g rg-lowtide -n stlowtiderespaldo --query id -o tsv)/blobServices/default/containers/respaldos"
```

Quien baje los respaldos necesita además `Storage Blob Data Reader` en el mismo contenedor, con `--assignee` y su correo: con las llaves de la cuenta apagadas, ser dueño de la suscripción no alcanza para leer blobs. La política de inmutabilidad queda sin bloquear: se puede quitar desde Azure con permisos de la suscripción, no con el rol de la VM. Bloquearla es irreversible. La llave de age se crea en la PC con `age-keygen`: la pública (`age1...`) va a la VM y la privada nunca sale de la PC y del gestor de contraseñas.

Para enterarse si los respaldos dejan de llegar, una alerta de Azure Monitor que manda correo si en 24 horas no hubo ninguna subida con éxito (cuesta unos centavos al mes):

```bash
az monitor action-group create -g rg-lowtide -n ag-respaldo --short-name respaldo --action email aviso <correo>
az monitor metrics alert create -g rg-lowtide -n respaldo-sin-subida \
  --scopes "$(az storage account show -g rg-lowtide -n stlowtiderespaldo --query id -o tsv)/blobServices/default" \
  --condition "total Transactions < 1 where ApiName includes PutBlob and ResponseType includes Success" \
  --window-size 24h --evaluation-frequency 1h --action ag-respaldo
```

En la VM, desde `/opt/lowtide/BackKL`:

```bash
sudo apt-get install -y age
sudo install -d -m 700 /etc/lowtide /var/backups/lowtide
sudo install -m 600 db/respaldo/respaldo.conf.example /etc/lowtide/respaldo.conf   # y se llenan RECEPTOR_AGE, CUENTA_BLOB y CONTENEDOR_BLOB
sudo install -m 644 db/respaldo/lowtide-respaldo.service db/respaldo/lowtide-respaldo.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lowtide-respaldo.timer
sudo systemctl start lowtide-respaldo.service   # el primero, para ver que sube
journalctl -u lowtide-respaldo -n 20 --no-pager
```

`respaldar.sh` se niega si `/etc/lowtide/respaldo.conf` es un enlace, no es de root o el grupo u otros pueden escribirla: quien la cambie decide para quién se cifran los respaldos. La ejecución falla si falta el contenedor de la API, el volumen de cartas, la llave o el espacio tmpfs. El registro dice `respaldo: cirdan_<fecha>_<sufijo>.backup.age, <bytes> bytes, sha256 ...`, `respaldo: subido a ...` y `respaldo: listo`. `systemctl list-timers lowtide-respaldo.timer` da la siguiente corrida. Un `403` al subir es que falta el rol de la identidad en el contenedor, o que el rol se acaba de dar y Azure tarda unos minutos en verlo. Si la subida falla, la unidad queda en `failed` con cuántos respaldos locales faltan por subir, y la corrida del día siguiente los vuelve a intentar.

### Restaurar

Para recuperar el conjunto completo se usa `restaurar_completo.sh`. Siempre crea una base y un volumen Docker nuevos; nunca borra ni reemplaza los existentes. Desencripta en `/run` (o `/run/lock` si `/run` no es escribible), siempre en tmpfs, recrea una nueva versión de la llave en Key Vault, y valida con AES-GCM y las huellas de la base cada carta referenciada antes de terminar. La cuenta que ejecuta la restauración necesita `az login`, permisos para crear una versión del secreto y acceso al contenedor de Postgres. El contenedor de la API aporta la imagen Python usada para poblar y verificar el volumen restaurado. Los contenedores temporales corren como root sin red y con capacidades limitadas para leer los temporales privados; el volumen y sus archivos quedan a nombre del usuario de la API.

```bash
az storage blob download --auth-mode login --account-name stlowtiderespaldo -c respaldos -n <blob> -f <blob>
AGE_IDENTIDAD=<ruta del archivo de la llave privada> db/respaldo/restaurar_completo.sh \
  <blob> cirdan-pg16 cirdan-api cirdan_restaurada lowtide-cartas-restauradas <boveda> carta-encryption-key
```

`AGE_IDENTIDAD` es la ruta del archivo de la llave, nunca la llave misma; con `AGE_IDENTIDAD=-` la lee de stdin para no dejarla en un archivo. El script comprueba que la base y el volumen nuevos no existan, nunca sobrescribe datos y solo devuelve la URL versionada de Key Vault, no la llave. Al terminar, pon en el `.env` las tres variables que imprime (`PGDATABASE`, `CARTA_VOLUME_NAME` y `CARTA_KEY_VAULT_SECRET_URL`), detén y recrea la API. Cuando esa verificación pasó, pon `CARTA_ALTA_ENABLED=true` en el `.env` para habilitar el alta. Si la verificación falla, no apuntes la API a esos destinos. El respaldo crea una base aparte para poder comparar primero con `db/respaldo/conteos.sql`; `db/respaldo/comparar.sh` también compara filas, RLS, FORCE, políticas y permisos. La restauración del plan B se hace en esa misma base nueva, no con `pg_restore --clean` sobre la base que ya está en uso.

`pruebas/test_respaldo.py` cubre el cifrado, la restauración de base, la retención y la subida simulada. `pruebas/test_respaldo_cartas.py` cubre el contenido seguro del paquete y, en el CI, la restauración de DB, volumen y llave y la autenticación AES-GCM de la carta. En una PC, las pruebas con Docker solo corren si se indican `RESPALDO_CONTENEDOR` y `RESPALDO_CARTAS_CONTENEDOR` de una pila aislada; nunca usan por omisión los contenedores de desarrollo.

## Plan B

En una PC del equipo, la misma pila con un túnel propio (otro `TUNNEL_TOKEN`). Para pasar el tráfico se cambia en Cloudflare el destino de `lowtidesec.com` y `www.lowtidesec.com` al túnel del plan B. Al probarlo se anotan la fecha, los pasos y los minutos hasta que respondió lowtidesec.com (comentario 10383 de RC-91).

### Carpeta y volumen

El plan B no usa la base de desarrollo de esa PC: sus datos son de prueba y las cuentas reales de la VM no existen ahí.

1. En la carpeta de desarrollo, `docker compose down` (sin `-v`, la base de desarrollo se queda). Hace falta porque `cirdan-pg16`, `cirdan-valkey` y `cirdan-api` tienen nombre fijo y el plan B los volvería a crear.
2. Un clon aparte de BackKL y FrontKL, por ejemplo en `C:\lowtide-planb\BackKL` y `C:\lowtide-planb\FrontKL`, en el mismo commit que la VM. En la VM, `git -C BackKL rev-parse HEAD` y `git -C FrontKL rev-parse HEAD` dan los dos commits, y en cada clon del plan B `git checkout <commit>` los fija. Con otro commit el portal o la API pueden esperar otra versión de la base que la del respaldo de la VM.
3. Su `.env` como el de la VM (paso 2 de 'Antes de levantar'), con el `TUNNEL_TOKEN` del plan B, sin `TOTP_KEY_VAULT_SECRET_URL` ni `PASSWORD_HASH_KEY_VAULT_SECRET_URL` (su llave va en `PASSWORD_HASH_ENCRYPTION_KEY`, sección 'Llave de las huellas de contraseña') y además `COMPOSE_PROJECT_NAME=lowtide-planb` (viene comentada en `.env.example`). Tampoco lleva `CARTA_KEY_VAULT_SECRET_URL`: la llave de cartas de la VM va en `CARTA_ENCRYPTION_KEY`, sacada de la bóveda igual que la del MFA. Sin ella, `CARTA_ALTA_ENABLED` tiene que quedar en false. Esa PC no tiene la identidad de la VM, así que la llave del MFA es la misma de la VM, pero va en `TOTP_ENCRYPTION_KEY`. Se toma del gestor de contraseñas ('LowTide vm-lowtide TOTP_ENCRYPTION_KEY') o de la bóveda con la sesión de `az` de quien la administra (`az keyvault secret show --id <URL con versión del .env de la VM> --query value -o tsv`). Mientras dure el plan B puede ir en ese `.env`, y al terminar se borra de ahí. Con otra llave TOTP los secretos de las cuentas reales no se descifran y nadie pasa la verificación en dos pasos. Sin `COMPOSE_PROJECT_NAME`, el proyecto toma el nombre de la carpeta: `C:\lowtide-planb\BackKL` da `backkl`, el mismo que la carpeta de desarrollo, y los dos usan el mismo volumen de la base, así que el `pg_restore --clean` y el `down -v` de abajo borrarían la base de desarrollo. Las contraseñas de PostgreSQL y Valkey pueden ser otras.
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

Al terminar, en la carpeta del plan B, la primera línea de `docker compose config` tiene que ser otra vez `name: lowtide-planb`, porque una `COMPOSE_PROJECT_NAME` puesta en la terminal le gana al `.env` y `docker volume ls` lista todos los volúmenes, no dice cuál borra esa carpeta. Con ese nombre, `docker compose down -v` borra `lowtide-planb_cirdan-pg16-data`, que trae los datos reales. Con otro nombre no se corre. En la carpeta de desarrollo, `docker compose up -d` levanta otra vez la pila local con su base de siempre.

### Plan B de pruebas (RC-277)

La misma pila en la PC de Ernesto, de respaldo por si la VM cae: otro túnel que publica solo `pruebas.lowtidesec.com`. ZAP activo (RC-89), ASVS (RC-136) y el pentest (RC-153) van contra el producto final en la VM, nunca contra esta pila (`docs/politica_uso_etico.md`). Queda abierto, como la VM, pero el túnel solo está arriba en las ventanas de prueba. No trae datos de la VM.

1. Ernesto crea en Zero Trust el túnel de pruebas con un solo nombre público, `pruebas.lowtidesec.com`, con destino `http://portal:3000`. Ni `lowtidesec.com` ni su www apuntan a ese túnel.
2. El paso 2 de 'Carpeta y volumen', con los clones en otra carpeta (por ejemplo `C:\lowtide-pruebas\`) y en el commit que se quiere probar. El paso 1 no hace falta: la pila de desarrollo puede seguir arriba con el archivo del paso 3.
3. `docker-compose.yml` fija `container_name` en `cirdan-pg16`, `cirdan-valkey` y `cirdan-api`, los mismos de la pila de desarrollo, y con ella arriba el `up` choca. En el clon de pruebas va un tercer archivo, `docker-compose.pruebas-pc.yml`, que les cambia el nombre. Es solo de esa PC: no se versiona ni se agrega con `git add`. El prefijo `lote14-` es el de las pilas aisladas de prueba. En redes que cortan UDP, cloudflared no sale por QUIC (UDP 7844) y el túnel cae con el error 1033 de Cloudflare. Con `TUNNEL_TRANSPORT_PROTOCOL: http2` va por TCP 443 y vuelve con sus 4 conexiones (prueba del 20 nov). `docker compose logs cloudflared` dice con qué protocolo registró cada conexión.

   ```yaml
   services:
     db:
       container_name: lote14-planb-pg16
     valkey:
       container_name: lote14-planb-valkey
     api:
       container_name: lote14-planb-api
     cloudflared:
       environment:
         TUNNEL_TRANSPORT_PROTOCOL: http2
   ```

4. Su `.env` sale de `.env.example`: `COMPOSE_FILE=docker-compose.yml:docker-compose.despliegue.yml:docker-compose.pruebas-pc.yml`, `COMPOSE_PATH_SEPARATOR=:`, `COMPOSE_PROJECT_NAME=lowtide-pruebas`, `ALLOWED_ORIGINS=https://pruebas.lowtidesec.com`, el `TUNNEL_TOKEN` del túnel de pruebas y llaves nuevas en `TOTP_ENCRYPTION_KEY` y `PASSWORD_HASH_ENCRYPTION_KEY`, distintas entre sí y de las de la VM. `COOKIE_SECURE`, `DEMO_ACCOUNTS`, `DEMO_EXPLORER`, `API_DOCS` y `FORWARDED_ALLOW_IPS` los fija `docker-compose.despliegue.yml`, diga lo que diga el `.env`. `WEBAUTHN_RP_ID` se queda en `lowtidesec.com`, que también sirve en el subdominio.
5. La primera línea de `docker compose config` es `name: lowtide-pruebas` y `docker compose config --format json` trae los tres `container_name` con `lote14-planb-`. Después, `docker compose up -d --build`: la base nueva se carga con las semillas y `docker compose logs demo-accounts` dice que las cuentas de demo quedaron apagadas.
6. Las cuentas de prueba las da de alta Ernesto. Nunca se usan las de demo, que tienen contraseña y secreto TOTP en el repo público (comentario 10312 de RC-91).

En cada ventana de prueba:

- Al abrir, `docker compose up -d`. Se anotan la hora y los minutos hasta que `https://pruebas.lowtidesec.com/login` respondió 200.
- La prueba de punta a punta: login con MFA, ver un dominio y cerrar sesión, sin 403. La respuesta del login trae `Set-Cookie: lt_session` con `Secure` (RC-286). Un login con una X-Forwarded-For inventada cuenta el fallo con la IP real, y 20 fallos desde una IP no bloquean el login desde otra.
- Esas dos pruebas de fallos van desde un navegador, con correos inventados, no con curl. El captcha se revisa antes de contar el fallo (`cirdan/auth/routes.py:221`): sin resolverlo, curl recibe 401 y el contador no sube. La X-Forwarded-For inventada se agrega a cada `POST /auth/login` que manda la página. El contador de cada IP es `login:fail:ip:<ip>` en Valkey (una IPv6 cuenta por su /64) y vence 15 min después del primer fallo (`LOCK_SECONDS`, `cirdan/auth/sessions.py:37`), así que los fallos van seguidos y se lee en seguida: `docker compose exec valkey sh -c 'valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning --scan --pattern "login:fail:ip:*"'` lista las IP que contaron. El mismo comando con `get login:fail:ip:<ip>` en lugar de `--scan --pattern ...` da cuántos fallos lleva esa IP.
- Por este túnel no va ninguna prueba activa. ZAP activo, ASVS y el pentest van contra la VM por `lowtidesec.com`, con una cuenta de prueba que da de alta Ernesto. Cómo se le abre paso al escáner en Cloudflare durante la ventana y cómo se cierra después va en RC-89.
- Al cerrar, `docker compose stop` (la base se queda) y se anota la hora. `docker inspect -f '{{.State.StartedAt}} {{.State.FinishedAt}}' lowtide-pruebas-cloudflared-1` da las dos horas del túnel en UTC. Con `restart: unless-stopped`, un contenedor detenido a mano no vuelve a arrancar al reiniciar la PC. Uno que no se detuvo sí: si la PC se apaga o se reinicia a mitad de una ventana, Docker Desktop vuelve a levantar el túnel. Por eso el `stop` va antes de apagar, y al prender la PC fuera de una ventana se revisa `docker compose ps`. Si cloudflared quedó arriba, se detiene y se anota el rato que estuvo publicado.
- Las horas de cada ventana van en un comentario de RC-277.

## Pruebas

`python -m unittest pruebas/test_despliegue.py` arma la config con valores falsos y revisa todo lo de arriba, sin crear nada. El CI la corre con las pruebas sin base ni red. `pruebas/test_llave_totp.py` revisa la lectura de Key Vault con una identidad y una bóveda falsas, sin red: la URL con versión, el token, los reintentos y el plazo de IMDS y de la bóveda, que el token no quede en el traceback, una sola lectura por proceso aunque lleguen muchas peticiones juntas y que la API no arranque sin llave. `pruebas/test_despliegue.py` también revisa que la IP de la API en la regla de IMDS sea la del compose y que el HEALTHCHECK le dé más tiempo que ese plazo. `pruebas/test_rotar_totp.py` revisa la rotación de la llave del MFA sin red: que la anterior abra y el secreto se vuelva a cifrar con la actual tras un código bueno, el 401 con 'Habla con el Admin.' y su evento cuando ninguna abre, las variables, el conteo de `contar_totp` (con 'sin acceso' y error con la entrada vacía) y `restablecer_mfa`, que solo restablece un secreto que no abre con ninguna. `pruebas/test_demo_cuentas.py` revisa que el script de demo apague las cuentas y que no termine bien sin llave del MFA, y `pruebas/test_bloqueo_ip.py` el contador por /64, las dos dentro del contenedor.

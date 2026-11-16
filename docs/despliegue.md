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
   - La llave del MFA. En la VM va `TOTP_KEY_VAULT_SECRET_URL` y no va `TOTP_ENCRYPTION_KEY` (sección 'Llave del MFA en Azure Key Vault'). En el plan B es al revés (paso 3 de 'Carpeta y volumen'). Con las dos puestas, o con ninguna, la API no arranca.
   - La llave de las huellas de contraseña, con la misma regla: en la VM `PASSWORD_HASH_KEY_VAULT_SECRET_URL` y no `PASSWORD_HASH_ENCRYPTION_KEY`, y en el plan B al revés (sección 'Llave de las huellas de contraseña').
3. En Cloudflare:
   - Zero Trust: el túnel publica `lowtidesec.com` y `www.lowtidesec.com` hacia `http://portal:3000`.
   - SSL/TLS > Edge Certificates: 'Always Use HTTPS' prendido. Sin él el portal también responde por `http://` y el formulario de login manda la contraseña sin cifrar hasta Cloudflare (la API la rechaza después por el Origin, pero ya viajó). Se comprueba con `curl -sI http://lowtidesec.com/login` y `curl -sI http://www.lowtidesec.com/login`: los dos responden 301 con `Location: https://...`. HSTS queda para RC-89.
4. `docker login` con `DOCKERHUB_USERNAME` y `DOCKERHUB_TOKEN` de la cuenta 'lowtidesec' (solo lectura).
5. Docker Engine reciente, con Compose 2.24 o más nuevo. Las redes `borde` e `interna` usan `gateway_mode_ipv4=isolated` y los puertos se quitan con `ports: !reset []`. Un Docker viejo rechaza la opción de red y `up` falla: nunca levanta la pila sin el aislamiento. Se probó con Docker Engine 29.8 y Compose 5.5.
6. Las bases de DB-IP Lite en `datos/geo/` de la carpeta de BackKL de la VM: `dbip-asn-lite-AAAA-MM.mmdb` y `dbip-country-lite-AAAA-MM.mmdb`, del mes más nuevo. Se bajan a mano con el OK de quien administra la VM, como dice el README (sección 'Geolocalización y ASN de las IP'), y la imagen las copia al construirse. No van en git. Sin ellas los activos `ip` salen sin país ni ASN y Shodan no consulta en InternetDB ninguna IP fuera de los rangos de CDN, así que el escaneo queda parcial y no da `exposed_service` (RC-49). Se revisa después de levantar con `docker compose exec api python -m cirdan.recolectores.geoip 8.8.8.8`, que sale con código 1 si falta una base.

## Levantar

Con `COMPOSE_FILE` en el `.env` (paso 2), desde la carpeta de BackKL:

```bash
docker compose up -d --build
docker compose logs demo-accounts
```

La segunda línea tiene que decir 'DEMO_ACCOUNTS no es true: se apagan las cuentas de demo.' y luego 'cuenta de demo apagada:' con cada una de las 5 cuentas de `CUENTAS` de `cirdan/auth/demo.py`. El script les vuelve a poner el hash de relleno de la semilla y les quita el secreto TOTP en cada `up`. Así, aunque el volumen de la base ya trajera la contraseña y el MFA públicos (por ejemplo el de una PC de desarrollo), esas cuentas dejan de entrar (comentario 10420 de RC-91). Una cuenta inactiva o de una empresa que no está activa también sale 'apagada', porque el cambio va por su id. Si no hay fila con ese id en esa empresa (borrada o con otro id), sale 'cuenta de demo que no puede iniciar sesión, nada que apagar:' cuando ese correo no puede iniciar sesión, y 'cuenta de demo con otro id y sin la contraseña de demo, no se toca:' cuando puede, pero no con la contraseña pública. Si no llega a la base, o si ese correo todavía entra con la contraseña pública, el servicio termina con error y la API, que lo espera, no arranca. Lo mismo pasa si esa otra fila trae una huella cifrada (`lt1$`) y la llave de las huellas está en Key Vault, porque demo-accounts no llega a IMDS: el error dice 'No se revisó si entran con la contraseña pública' y nombra los correos. Se arregla con esa fila de la base: desactivarla (`is_active = false`) o cambiarle el correo a uno que no esté en `CUENTAS`, y volver a correr `up`.

## Lo que fija el archivo del despliegue

Ningún .env le gana a estos valores:

- `DEMO_ACCOUNTS=false` y `DEMO_EXPLORER=false`.
- `COOKIE_SECURE=true`, porque el despliegue siempre va con HTTPS.
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
- La URL lleva la versión del secreto, y la API no acepta una sin versión. Así cargar otro valor en la bóveda, por error o pensando que es una rotación, no cambia la llave que lee la API en el siguiente reinicio: hace falta editar el `.env`. La API solo revisa que la llave mida 32 bytes, no que descifre los secretos de la base. Con otra llave arranca `healthy` y nadie pasa la verificación en dos pasos.
- Si Key Vault o la identidad fallan, la API no arranca y `docker compose logs api` dice por qué (HTTP 403 es que falta el rol y HTTP 404, que el nombre o la versión de la URL no existen, y ese no se reintenta). Ningún mensaje lleva el token ni la llave. Cada lectura reintenta hasta 90 s en total, para aguantar un IMDS que se está actualizando, y el HEALTHCHECK del Dockerfile le da 200 s antes de contar fallos, porque con la llave de las huellas también en Key Vault (RC-330) son dos lecturas seguidas, cada una con sus 90 s. Si se rinde, uvicorn sale y `restart: unless-stopped` la vuelve a levantar.
- Lo que no cambia: quien sea root en la VM puede pedir el mismo token. Un contenedor que no sea la API no puede, por la regla de 'Solo la API llega a IMDS'. Lo que se gana es que cada lectura queda en el registro de la bóveda y que quitar el rol corta el acceso.
- Costo: Key Vault Standard cobra 0.03 USD por cada 10 mil operaciones, sin cuota por bóveda. Por cada llave en Key Vault la API hace dos peticiones por arranque, una a la identidad y otra a la bóveda, y solo la de la bóveda cuenta como operación. Con la del MFA y la de las huellas son cuatro peticiones y dos operaciones.

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

Para regresar, se pone otra vez `TOTP_ENCRYPTION_KEY` en el `.env` con la copia del gestor de contraseñas, se borra `TOTP_KEY_VAULT_SECRET_URL` y se repite el paso 10. La copia del gestor se queda siempre: el plan B la usa y, sin ella o sin la bóveda, los secretos TOTP de la base ya no se descifran. Rotar la llave pide volver a cifrar los secretos TOTP de todas las cuentas, y no hay herramienta para eso: una versión nueva en la bóveda no se usa hasta que alguien cambie la URL del `.env`.

## Llave de las huellas de contraseña (RC-330)

La huella argon2id de cada contraseña se guarda cifrada con AES-256-GCM (`cirdan/auth/passwords.py`): `lt1$` más la cadena PHC cifrada, con el id del usuario como dato asociado. Con un volcado de la base, sin la llave, no se pueden probar contraseñas fuera de línea, y la huella de una cuenta copiada a otra no abre. La llave es otra que la del MFA: la API compara los bytes de las dos al arrancar y no arranca si son la misma, aunque una venga del `.env` y la otra de Key Vault, y tampoco acepta dos versiones del mismo secreto. Sigue la misma regla que la del MFA: en la VM, la URL de su secreto de Key Vault en `PASSWORD_HASH_KEY_VAULT_SECRET_URL`, y en desarrollo, el CI y el plan B, la llave misma en `PASSWORD_HASH_ENCRYPTION_KEY`. Una de las dos, y sin llave la API no arranca, igual que el script de demo.

- Las huellas de antes, sin cifrar, entran todavía y quedan cifradas en ese mismo inicio de sesión. No hace falta restablecer contraseñas. El hash de relleno de las semillas y de `cirdan/auth/demo.py` no cambia y sigue sin abrir nada.
- Si la llave se pierde, ninguna contraseña guardada vuelve a abrir y cada cuenta se restablece con su script de alta. Por eso la copia del gestor de contraseñas se queda siempre, como la del MFA.
- Si el cambio se revierte, el código viejo no abre las huellas cifradas: las cuentas que ya entraron se restablecen igual.
- Rotar la llave no pide contraseñas nuevas, porque se descifra la huella y se vuelve a cifrar. Ese script todavía no existe: el `1` de `lt1$` es la versión de la llave para cuando exista.

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

## Respaldo diario (RC-233)

Una vez al día, a las 09:00 UTC (03:00 en Monterrey), `lowtide-respaldo.timer` corre `db/respaldo/respaldar.sh`:

1. Espera hasta 5 minutos a que `cirdan-pg16` acepte conexiones: si la VM estaba apagada a esa hora, el timer corre al arrancar, antes que la base.
2. `pg_dump -Fc` de la base `cirdan` con el usuario postgres dentro de `cirdan-pg16`. Nunca con `cirdan_app`, que con FORCE RLS no ve todas las filas.
3. Lo cifra al vuelo con [age](https://age-encryption.org) y una llave pública. El respaldo sin cifrar nunca toca el disco. La llave privada no está en la VM: vive en la PC de Ernesto, cifrada con DPAPI, y en el gestor de contraseñas. Quien entre a la VM no puede leer los respaldos.
4. Deja `cirdan_<fecha UTC>_<8 hex al azar>.dump.age` en `/var/backups/lowtide` (carpeta 700, archivo 600). El sufijo al azar hace que nadie pueda ocupar antes en Azure el nombre del respaldo de mañana.
5. Lo sube a un contenedor de Azure Blob con la identidad administrada de la VM, la misma de Key Vault. No hay llave de almacenamiento en la VM: el token sale de IMDS y llega a `curl` por stdin. La subida nunca escribe encima de un blob con el mismo nombre (`If-None-Match: *`), Azure revisa el MD5 del archivo y el blob lleva su sha256 en `x-ms-meta-sha256`. Si `curl` reintenta una subida que sí llegó, Azure responde `403 UnauthorizedBlobOverwrite`, porque la identidad no puede escribir encima, y el respaldo cuenta como subido solo si el blob que ya está tiene el mismo MD5. En cada corrida también sube los respaldos locales que todavía no están en Azure, así que una subida que falló un día se repite al siguiente.
6. Conserva en la VM los respaldos de los últimos 7 días que tienen alguno (una corrida a mano no le quita su lugar a un día). Nunca borra uno que no está en Azure, salvo que ya haya más de 31. La retención solo borra archivos con ese nombre exacto dentro de esa carpeta.

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
sudo install -m 600 db/respaldo/respaldo.conf.example /etc/lowtide/respaldo.conf   # y se llenan RECEPTOR_AGE y CUENTA_BLOB
sudo install -m 644 db/respaldo/lowtide-respaldo.service db/respaldo/lowtide-respaldo.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lowtide-respaldo.timer
sudo systemctl start lowtide-respaldo.service   # el primero, para ver que sube
journalctl -u lowtide-respaldo -n 20 --no-pager
```

`respaldar.sh` se niega si `/etc/lowtide/respaldo.conf` es un enlace, no es de root o el grupo u otros pueden escribirla: quien la cambie decide para quién se cifran los respaldos. El registro dice `respaldo: cirdan_<fecha>_<sufijo>.dump.age, <bytes> bytes, sha256 ...`, `respaldo: subido a ...` y `respaldo: listo`. `systemctl list-timers lowtide-respaldo.timer` da la siguiente corrida. Un `403` al subir es que falta el rol de la identidad en el contenedor, o que el rol se acaba de dar y Azure tarda unos minutos en verlo. Si la subida falla, la unidad queda en `failed` con cuántos respaldos locales faltan por subir, y la corrida del día siguiente los vuelve a intentar.

### Restaurar

`db/respaldo/restaurar.sh` siempre crea una base nueva con otro nombre. Nunca hace DROP DATABASE ni escribe sobre `cirdan`, y se niega si la base ya existe. Antes de crearla descifra el respaldo completo: con otra llave o un archivo cortado falla sin dejar ninguna base. Después de restaurar le quita TEMPORARY a PUBLIC, como la migración 004, porque `pg_dump` no guarda los permisos de la base. Se corre donde esté la llave privada, en Git Bash o Linux, contra el contenedor de una base de Postgres 16 con los roles de `db/init`, por ejemplo una pila aislada:

```bash
az storage blob download --auth-mode login --account-name stlowtiderespaldo -c respaldos -n <blob> -f <blob>
AGE_IDENTIDAD=<ruta del archivo de la llave privada> db/respaldo/restaurar.sh <blob> <contenedor> cirdan_restaurada
```

`AGE_IDENTIDAD` es la ruta del archivo de la llave, nunca la llave misma, y con `AGE_IDENTIDAD=-` la lee de stdin para no dejarla en un archivo (así la manda el script de restauración de la PC de Ernesto, que también revisa el sha256 del blob bajado). Para saber si la restauración quedó completa se corre `db/respaldo/conteos.sql` como postgres en la base de la VM y en la restaurada, y se comparan las dos salidas: filas por tabla, RLS, FORCE, políticas y los permisos de PUBLIC sobre la base. Las tablas que cambiaron después del respaldo (la bitácora, por ejemplo) pueden traer más filas en la VM. `db/respaldo/comparar.sh` hace esa comparación solo entre dos bases del mismo contenedor: en una pila aislada, su `cirdan` es la de las semillas, no la de la VM. Para volver a poner un respaldo en la base de producción se siguen los pasos de 'Copiar los datos de la VM' en el plan B, con su `pg_restore --clean`.

`pruebas/test_respaldo.py` saca un respaldo de la base del compose de prueba, lo restaura en una base nueva y compara todo, y revisa la retención por días, que la restauración no pise ninguna base ni deje una vacía con otra llave, que no muestre la llave, que la configuración no la pueda cambiar otro usuario y que una configuración mala no deje nada. Corre en el CI con las pruebas de la base. No prueba la subida a Azure, que se revisa en la VM con el primer `systemctl start`.

## Plan B

En una PC del equipo, la misma pila con un túnel propio (otro `TUNNEL_TOKEN`). Para pasar el tráfico se cambia en Cloudflare el destino de `lowtidesec.com` y `www.lowtidesec.com` al túnel del plan B. Al probarlo se anotan la fecha, los pasos y los minutos hasta que respondió lowtidesec.com (comentario 10383 de RC-91).

### Carpeta y volumen

El plan B no usa la base de desarrollo de esa PC: sus datos son de prueba y las cuentas reales de la VM no existen ahí.

1. En la carpeta de desarrollo, `docker compose down` (sin `-v`, la base de desarrollo se queda). Hace falta porque `cirdan-pg16`, `cirdan-valkey` y `cirdan-api` tienen nombre fijo y el plan B los volvería a crear.
2. Un clon aparte de BackKL y FrontKL, por ejemplo en `C:\lowtide-planb\BackKL` y `C:\lowtide-planb\FrontKL`, en el mismo commit que la VM. En la VM, `git -C BackKL rev-parse HEAD` y `git -C FrontKL rev-parse HEAD` dan los dos commits, y en cada clon del plan B `git checkout <commit>` los fija. Con otro commit el portal o la API pueden esperar otra versión de la base que la del respaldo de la VM.
3. Su `.env` como el de la VM (paso 2 de 'Antes de levantar'), con el `TUNNEL_TOKEN` del plan B, sin `TOTP_KEY_VAULT_SECRET_URL` ni `PASSWORD_HASH_KEY_VAULT_SECRET_URL` (su llave va en `PASSWORD_HASH_ENCRYPTION_KEY`, sección 'Llave de las huellas de contraseña') y además `COMPOSE_PROJECT_NAME=lowtide-planb` (viene comentada en `.env.example`). Esa PC no tiene la identidad de la VM, así que la llave del MFA es la misma de la VM, pero va en `TOTP_ENCRYPTION_KEY`. Se toma del gestor de contraseñas ('LowTide vm-lowtide TOTP_ENCRYPTION_KEY') o de la bóveda con la sesión de `az` de quien la administra (`az keyvault secret show --id <URL con versión del .env de la VM> --query value -o tsv`). Mientras dure el plan B puede ir en ese `.env`, y al terminar se borra de ahí. Con otra llave TOTP los secretos de las cuentas reales no se descifran y nadie pasa la verificación en dos pasos. Sin `COMPOSE_PROJECT_NAME`, el proyecto toma el nombre de la carpeta: `C:\lowtide-planb\BackKL` da `backkl`, el mismo que la carpeta de desarrollo, y los dos usan el mismo volumen de la base, así que el `pg_restore --clean` y el `down -v` de abajo borrarían la base de desarrollo. Las contraseñas de PostgreSQL y Valkey pueden ser otras.
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

## Pruebas

`python -m unittest pruebas/test_despliegue.py` arma la config con valores falsos y revisa todo lo de arriba, sin crear nada. El CI la corre con las pruebas sin base ni red. `pruebas/test_llave_totp.py` revisa la lectura de Key Vault con una identidad y una bóveda falsas, sin red: la URL con versión, el token, los reintentos y el plazo de IMDS y de la bóveda, que el token no quede en el traceback, una sola lectura por proceso aunque lleguen muchas peticiones juntas y que la API no arranque sin llave. `pruebas/test_despliegue.py` también revisa que la IP de la API en la regla de IMDS sea la del compose y que el HEALTHCHECK le dé más tiempo que ese plazo. `pruebas/test_demo_cuentas.py` revisa que el script de demo apague las cuentas y que no termine bien sin llave del MFA, y `pruebas/test_bloqueo_ip.py` el contador por /64, las dos dentro del contenedor.

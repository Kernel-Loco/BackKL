# Infraestructura como código con Terraform (#81, RC-132)

`terraform apply` crea en Azure una VM equivalente a `vm-lowtide` (#49, RC-91) con su red, un grupo de seguridad que
solo abre 443 y SSH a las IPs del equipo, disco cifrado y cloud-init que instala Docker y levanta el compose del
despliegue. `terraform destroy` la borra. El código está en `infra/terraform/`.

## En pocas palabras (para la presentación)

Terraform es una **receta escrita en código** para la infraestructura. En vez de dar clics en el portal de Azure,
escribimos en archivos *qué* queremos: una VM, su red, un firewall y un disco cifrado. Con `terraform apply`,
Terraform compara la receta con lo que ya existe en Azure y crea solo lo que falta. `terraform destroy` borra todo.

Por qué importa para la seguridad:

- **Repetible y revisable.** La infraestructura pasa por PR y revisión como el código: si alguien abre un puerto de
  más, se ve en el diff.
- **Se revisa antes de existir.** Trivy lee la receta en el CI y frena el PR si encuentra una configuración insegura
  alta o crítica (un puerto abierto a todo internet, un disco sin cifrar).
- **Sin secretos en el repo ni en el estado.** La VM entra solo con llave SSH y arma sus contraseñas dentro de ella.
- **Recuperación.** Si la VM se pierde, se vuelve a levantar idéntica con un comando.

## Qué crea

Todo va en un grupo de recursos propio, `rg-lowtide-iac`. Nunca en `rg-lowtide`, el de la VM manual: la variable lo
rechaza, porque `terraform destroy` borra el grupo entero.

| Recurso | Para qué |
|---|---|
| `azurerm_virtual_network` y `azurerm_subnet` | Red 10.80.0.0/16, que no choca con las redes fijas de Docker (10.249.91-93.x). |
| `azurerm_network_security_group` | Entra solo 22 (SSH) y 443, y los dos solo desde `ips_equipo`. Lo demás lo tira la regla `DenyAllInBound` de Azure. Va en la subred y en la tarjeta de red. |
| `azurerm_public_ip` | IP fija para entrar por SSH. |
| `azurerm_linux_virtual_machine` | Ubuntu 24.04, `Standard_B2s`, solo con llave SSH, Trusted Launch (arranque seguro y vTPM), cifrado en el host, identidad administrada y diagnóstico de arranque. |
| `azurerm_dev_test_global_vm_shutdown_schedule` | Se apaga sola a las 23:00 de Monterrey para no gastar crédito. |
| `azurerm_role_assignment` (opcional) | Lectura de un solo secreto de Key Vault: el token del túnel, si se usa. |

### Primer arranque (cloud-init)

`infra/terraform/cloud-init.yaml.tftpl` hace lo mismo que los pasos a mano de `docs/despliegue.md`, en este orden:

1. **`lowtide-imds`**: la regla 'Solo la API llega a IMDS', la misma unidad de systemd de `docs/despliegue.md`. Va antes de instalar Docker y Docker no arranca sin ella (`RequiredBy=docker.service`).
2. **Docker Engine y Compose** desde el repositorio oficial de Docker.
3. **`lowtide-arranque`**: clona BackKL y FrontKL (rama `main` por omisión) en `/opt/lowtide`, arma el `.env` y
   corre `docker compose up -d --build` con `docker-compose.yml` y `docker-compose.despliegue.yml`. Se niega a
   levantar la pila si la regla de IMDS no está.

El `.env` lo arma `lowtide-env` dentro de la VM, como el CI: contraseñas de PostgreSQL y Valkey y llaves del MFA y de
las huellas al azar, `COOKIE_SECURE=true`, `ALLOWED_ORIGINS=https://<nombre_publico>` y `DEMO_ACCOUNTS=false`. Queda
con permisos 600 y no se vuelve a tocar en los siguientes arranques, porque la base ya se creó con esas contraseñas.
Esta VM empieza con su propia base, solo con las semillas, sin cuentas ni datos reales.

## Sin túnel por omisión

El túnel de Cloudflare es lo que conecta `lowtidesec.com` con la VM. Si esta VM usara el mismo token que
`vm-lowtide`, Cloudflare repartiría las visitas de lowtidesec.com entre las dos, y la mitad de los usuarios caería en
esta VM, que tiene la base vacía. Por eso, sin configurar nada, **esta VM no levanta cloudflared** y ningún nombre
público llega a ella: se revisa por SSH.

Para publicarla con su propio nombre (por ejemplo `iac.lowtidesec.com`), quien administra Cloudflare crea **otro**
túnel hacia `http://portal:3000`. Quien administra Azure guarda su token como secreto de Key Vault, y en
`terraform.tfvars` van `nombre_publico`, `tunel_boveda_id` y `tunel_secreto_url` (la URL con versión). Terraform le da
a la VM lectura solo de ese secreto. La VM lo lee al arrancar con su identidad, como la API lee la llave del MFA, y
nunca pasa por Terraform: no se usa `data "azurerm_key_vault_secret"`, que guardaría el valor en el estado.

## Usarlo

Desde la carpeta `infra/terraform`, con una cuenta de Azure que pueda crear recursos (Azure for Students sirve):

1. Instalar las herramientas (Mac): `brew install hashicorp/tap/terraform trivy azure-cli`. Entrar con `az login`.
2. Una vez por suscripción, para el cifrado en el host:

   ```bash
   az feature register --namespace Microsoft.Compute --name EncryptionAtHost
   az feature show --namespace Microsoft.Compute --name EncryptionAtHost --query properties.state   # hasta 'Registered'
   az provider register -n Microsoft.Compute
   ```

   Si la suscripción no deja registrarlo, va `cifrado_en_host = false`. El disco sigue cifrado en reposo por Azure,
   pero no la caché ni los temporales.
3. Llave SSH, si no hay: `ssh-keygen -t ed25519`. Terraform solo lee la pública (`~/.ssh/id_ed25519.pub`).
4. `cp terraform.tfvars.example terraform.tfvars` y poner en `ips_equipo` la IP de cada quien con `/32`
   (`curl -s https://ifconfig.me`). `terraform.tfvars` no va a git.
5. Crear:

   ```bash
   terraform init
   terraform plan -out=lowtide.tfplan      # muestra qué va a crear, sin crear nada
   terraform apply lowtide.tfplan
   ```

6. Comprobar (de 10 a 20 minutos la primera vez, lo que tarda en compilar la API y el portal):

   ```bash
   $(terraform output -raw ssh)
   sudo cloud-init status --wait
   sudo journalctl -u lowtide-arranque -f
   sudo iptables -S DOCKER-USER                 # la regla de IMDS va primero
   cd /opt/lowtide/BackKL && sudo docker compose ps     # db, valkey, api y portal 'healthy'
   sudo docker compose logs demo-accounts       # 'DEMO_ACCOUNTS no es true: se apagan las cuentas de demo.'
   ```

7. Borrar todo: `terraform destroy`. Borra el grupo `rg-lowtide-iac` con la VM, su disco y su IP.

Después de un apagado automático se prende con `az vm start -g rg-lowtide-iac -n vm-lowtide-iac`. La IP no cambia.

## Lo que no hace (todavía)

Frente a `vm-lowtide`, esta VM no tiene el respaldo diario a Azure Blob (RC-233) ni lee las llaves del MFA y de las
huellas de Key Vault: las suyas se generan en la VM y se pierden con `terraform destroy`, junto con su base. Es para
mostrar que la infraestructura se puede crear y borrar desde código, no para reemplazar la VM de producción. Para
eso habría que importar `vm-lowtide` al estado (`terraform import`), y eso lo decide Ernesto, que la administra.

El estado (`terraform.tfstate`) queda en la PC de quien corre `apply`. Si varias personas lo van a usar, el paso
siguiente es guardarlo en un contenedor de Azure Blob (`backend "azurerm"`) con bloqueo.

## Costo aproximado

Con Azure for Students (100 USD de crédito), en westus2: la B2s cuesta unos 0.04 USD por hora prendida (unos 30 USD
al mes sin apagarla), el disco StandardSSD de 64 GB unos 5 USD al mes y la IP pública unos 4 USD al mes. El disco y la
IP se cobran aunque la VM esté apagada. `terraform destroy` al terminar deja el costo en cero.

## Pruebas

- `python -m unittest -v pruebas/test_terraform.py`: sin nube ni red. El grupo de seguridad abre solo 22 y 443 a
  `ips_equipo`, el estado y las variables no van a git, Terraform no lee secretos, la regla de IMDS de cloud-init es
  la de `docs/despliegue.md` con la IP de la API del compose, sin túnel no se levanta cloudflared, y el script del
  `.env` corre sobre el `.env.example` real sin dejar valores de ejemplo.
- El job `terraform` del CI corre `terraform fmt -check`, `terraform validate` (sin cuenta de Azure) y
  `trivy config --severity HIGH,CRITICAL --exit-code 1`. Trivy deja pasar un solo aviso medio, justificado en
  `main.tf`: la IP pública (AZU-0076), que hace falta para SSH sin pagar Azure Bastion.

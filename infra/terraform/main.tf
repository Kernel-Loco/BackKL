# Red, grupo de seguridad y VM equivalente a vm-lowtide (#49, RC-91), en un grupo de recursos propio.

locals {
  con_tunel = var.tunel_secreto_url != ""
  # Nombre del secreto, para dar a la VM lectura solo de ese secreto y no de toda la bóveda.
  tunel_secreto_nombre = local.con_tunel ? regex("/secrets/([^/]+)/", var.tunel_secreto_url)[0] : ""

  etiquetas = {
    proyecto = "lowtide"
    jira     = "RC-132"
    creado   = "terraform"
  }
}

resource "azurerm_resource_group" "lowtide" {
  name     = var.grupo_recursos
  location = var.region
  tags     = local.etiquetas
}

# ------------------------------------------------------------------------------------------------- red

# 10.80.0.0/16 no choca con las redes fijas de Docker del despliegue (10.249.91-93.x).
resource "azurerm_virtual_network" "lowtide" {
  name                = "vnet-${var.nombre}"
  location            = azurerm_resource_group.lowtide.location
  resource_group_name = azurerm_resource_group.lowtide.name
  address_space       = ["10.80.0.0/16"]
  tags                = local.etiquetas
}

resource "azurerm_subnet" "vm" {
  name                 = "snet-vm"
  resource_group_name  = azurerm_resource_group.lowtide.name
  virtual_network_name = azurerm_virtual_network.lowtide.name
  address_prefixes     = ["10.80.1.0/24"]
}

# Solo entra SSH y 443, y los dos solo desde las IPs del equipo. Lo demás lo tira la regla DenyAllInBound que Azure
# pone al final de todo grupo de seguridad. Con el túnel de Cloudflare el portal no necesita ni 443 (sale hacia
# Cloudflare), pero queda como pide el ticket.
resource "azurerm_network_security_group" "vm" {
  name                = "nsg-${var.nombre}"
  location            = azurerm_resource_group.lowtide.location
  resource_group_name = azurerm_resource_group.lowtide.name
  tags                = local.etiquetas

  security_rule {
    name                       = "ssh-equipo"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = var.ips_equipo
    destination_address_prefix = "VirtualNetwork"
  }

  security_rule {
    name                       = "https-equipo"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefixes    = var.ips_equipo
    destination_address_prefix = "VirtualNetwork"
  }
}

resource "azurerm_subnet_network_security_group_association" "vm" {
  subnet_id                 = azurerm_subnet.vm.id
  network_security_group_id = azurerm_network_security_group.vm.id
}

resource "azurerm_public_ip" "vm" {
  name                = "pip-${var.nombre}"
  location            = azurerm_resource_group.lowtide.location
  resource_group_name = azurerm_resource_group.lowtide.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.etiquetas
}

resource "azurerm_network_interface" "vm" {
  name                = "nic-${var.nombre}"
  location            = azurerm_resource_group.lowtide.location
  resource_group_name = azurerm_resource_group.lowtide.name
  tags                = local.etiquetas

  ip_configuration {
    name                          = "principal"
    subnet_id                     = azurerm_subnet.vm.id
    private_ip_address_allocation = "Dynamic"
    # La IP pública es para entrar por SSH: el grupo de seguridad solo la abre a ips_equipo. Quitarla pide Azure
    # Bastion (unos 140 USD al mes), más de lo que da Azure for Students.
    #trivy:ignore:AZU-0076
    public_ip_address_id = azurerm_public_ip.vm.id
  }
}

# El mismo grupo de seguridad también en la tarjeta de red: si alguien cambia la subred, la VM sigue cubierta.
resource "azurerm_network_interface_security_group_association" "vm" {
  network_interface_id      = azurerm_network_interface.vm.id
  network_security_group_id = azurerm_network_security_group.vm.id
}

# ------------------------------------------------------------------------------------------------- VM

resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "vm-${var.nombre}"
  location              = azurerm_resource_group.lowtide.location
  resource_group_name   = azurerm_resource_group.lowtide.name
  size                  = var.tamano_vm
  admin_username        = var.usuario_admin
  network_interface_ids = [azurerm_network_interface.vm.id]
  tags                  = local.etiquetas

  # Solo con llave SSH: sin contraseña de Linux.
  disable_password_authentication = true
  admin_ssh_key {
    username   = var.usuario_admin
    public_key = file(pathexpand(var.llave_ssh_publica))
  }

  # Trusted Launch (arranque seguro y vTPM) y cifrado en el host, además del cifrado en reposo que Azure ya aplica a
  # todos los discos administrados.
  secure_boot_enabled        = true
  vtpm_enabled               = true
  encryption_at_host_enabled = var.cifrado_en_host

  os_disk {
    name                 = "osdisk-${var.nombre}"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = 64
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  # Identidad administrada, como vm-lowtide: con ella la VM lee de Key Vault sin guardar llaves. La regla de
  # lowtide-imds (cloud-init) deja que de los contenedores solo la API la use.
  identity {
    type = "SystemAssigned"
  }

  # cloud-init: Docker, la regla de IMDS y la pila de docker-compose.despliegue.yml. Sin secretos: el .env se arma
  # dentro de la VM con contraseñas al azar, y el token del túnel (si hay) se lee de Key Vault con la identidad.
  custom_data = base64encode(templatefile("${path.module}/cloud-init.yaml.tftpl", {
    rama              = var.rama
    nombre_publico    = var.nombre_publico
    tunel_secreto_url = var.tunel_secreto_url
  }))

  # Diagnóstico de arranque con almacenamiento administrado: la consola serie sirve si SSH no responde.
  boot_diagnostics {}
}

# Solo lectura y solo del secreto del token del túnel, como el rol de la llave del MFA en vm-lowtide.
resource "azurerm_role_assignment" "tunel" {
  count                = local.con_tunel ? 1 : 0
  scope                = "${var.tunel_boveda_id}/secrets/${local.tunel_secreto_nombre}"
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_virtual_machine.vm.identity[0].principal_id
  principal_type       = "ServicePrincipal"

  lifecycle {
    precondition {
      condition     = can(regex("^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.KeyVault/vaults/[^/]+$", var.tunel_boveda_id))
      error_message = "Con tunel_secreto_url también va tunel_boveda_id (sale de `az keyvault show -n <bóveda> --query id -o tsv`)."
    }
  }
}

# Se apaga sola cada noche para no gastar el crédito de Azure for Students. Se prende con `az vm start`.
resource "azurerm_dev_test_global_vm_shutdown_schedule" "vm" {
  count                 = var.apagado_diario == "" ? 0 : 1
  virtual_machine_id    = azurerm_linux_virtual_machine.vm.id
  location              = azurerm_resource_group.lowtide.location
  enabled               = true
  daily_recurrence_time = var.apagado_diario
  timezone              = "Central Standard Time (Mexico)"
  tags                  = local.etiquetas

  notification_settings {
    enabled = false
  }
}

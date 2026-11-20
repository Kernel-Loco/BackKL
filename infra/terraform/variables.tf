# Los valores de cada quien van en terraform.tfvars (copia de terraform.tfvars.example), que no va a git.

variable "suscripcion_id" {
  description = "Suscripción de Azure. null: la de ARM_SUBSCRIPTION_ID o la de `az account show`."
  type        = string
  default     = null
}

variable "region" {
  description = "Región de Azure. westus2 es la del respaldo de la VM manual (docs/despliegue.md)."
  type        = string
  default     = "westus2"
}

variable "grupo_recursos" {
  description = "Grupo de recursos nuevo. Nunca el de la VM manual (rg-lowtide): `terraform destroy` borra el grupo entero."
  type        = string
  default     = "rg-lowtide-iac"

  validation {
    condition     = var.grupo_recursos != "rg-lowtide"
    error_message = "rg-lowtide es el grupo de la VM manual de Ernesto. Terraform usa uno propio."
  }
}

variable "nombre" {
  description = "Prefijo de los recursos (VM, red, IP)."
  type        = string
  default     = "lowtide-iac"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.nombre))
    error_message = "Solo minúsculas, números y guiones, de 3 a 31 caracteres."
  }
}

variable "tamano_vm" {
  description = "Tamaño de la VM. Standard_B2s (2 vCPU, 4 GB) alcanza para compilar el portal y correr la pila."
  type        = string
  default     = "Standard_B2s"
}

variable "usuario_admin" {
  description = "Usuario de Linux para entrar por SSH."
  type        = string
  default     = "lowtide"
}

variable "llave_ssh_publica" {
  description = "Ruta de la llave SSH PÚBLICA (.pub) con la que se entra a la VM. Nunca la privada."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"

  validation {
    condition     = endswith(var.llave_ssh_publica, ".pub")
    error_message = "Va la llave pública (.pub), nunca la privada."
  }
}

variable "ips_equipo" {
  description = "IPs del equipo (CIDR, ej. 201.0.113.7/32) que pueden entrar por SSH y por 443. Ninguna abierta a todo internet."
  type        = list(string)

  validation {
    condition     = length(var.ips_equipo) > 0 && alltrue([for ip in var.ips_equipo : can(cidrhost(ip, 0))])
    error_message = "Pon al menos una IP en formato CIDR, por ejemplo 201.0.113.7/32."
  }

  validation {
    condition     = alltrue([for ip in var.ips_equipo : !startswith(ip, "0.0.0.0/") && !startswith(ip, "::/")])
    error_message = "0.0.0.0/0 abre la VM a todo internet. Solo van las IPs del equipo."
  }
}

variable "cifrado_en_host" {
  description = "Cifra en el host de Azure el disco, su caché y los temporales. Pide registrar EncryptionAtHost en la suscripción una vez (docs/terraform.md)."
  type        = bool
  default     = true
}

variable "rama" {
  description = "Rama de BackKL y FrontKL que la VM clona y levanta."
  type        = string
  default     = "main"

  validation {
    condition     = can(regex("^[A-Za-z0-9._/-]+$", var.rama))
    error_message = "Nombre de rama no válido."
  }
}

variable "nombre_publico" {
  description = "Nombre con que se abriría el portal (va en ALLOWED_ORIGINS). Nunca lowtidesec.com ni www: esos son de la VM manual."
  type        = string
  default     = "iac.lowtidesec.com"

  validation {
    condition     = can(regex("^[a-z0-9-]+(\\.[a-z0-9-]+)+$", var.nombre_publico)) && !contains(["lowtidesec.com", "www.lowtidesec.com"], var.nombre_publico)
    error_message = "Un nombre propio de esta VM, por ejemplo iac.lowtidesec.com. lowtidesec.com y www son de la VM manual."
  }
}

variable "tunel_boveda_id" {
  description = "Opcional. Id de recurso de la bóveda de Key Vault donde está el token de un túnel de Cloudflare PROPIO de esta VM. Vacío: la VM se levanta sin túnel."
  type        = string
  default     = ""
}

variable "tunel_secreto_url" {
  description = "Opcional. URL con versión del secreto del token del túnel (https://<bóveda>.vault.azure.net/secrets/<nombre>/<versión>). Nunca el token mismo."
  type        = string
  default     = ""

  validation {
    condition     = var.tunel_secreto_url == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+/[0-9a-f]{32}$", var.tunel_secreto_url))
    error_message = "La URL del secreto lleva su versión: https://<bóveda>.vault.azure.net/secrets/<nombre>/<versión>."
  }
}

variable "apagado_diario" {
  description = "Hora (HHMM, hora de Monterrey) a la que la VM se apaga sola para no gastar el crédito. Vacío: no se apaga."
  type        = string
  default     = "2300"

  validation {
    condition     = var.apagado_diario == "" || can(regex("^([01][0-9]|2[0-3])[0-5][0-9]$", var.apagado_diario))
    error_message = "Formato HHMM, por ejemplo 2300."
  }
}

# Infraestructura como código de LowTide (#81, RC-132). Guía: docs/terraform.md.
#
# El estado (terraform.tfstate) se queda en la PC de quien corre `terraform apply` y nunca va a git (.gitignore).
# No lleva secretos: la VM entra solo con llave SSH (aquí va la pública) y su .env se arma dentro de la VM.

terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  # null toma la suscripción de ARM_SUBSCRIPTION_ID o de `az account show`.
  subscription_id = var.suscripcion_id
}

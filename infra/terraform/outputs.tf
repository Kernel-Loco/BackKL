output "ip_publica" {
  description = "IP pública de la VM."
  value       = azurerm_public_ip.vm.ip_address
}

output "ssh" {
  description = "Comando para entrar a la VM."
  value       = "ssh ${var.usuario_admin}@${azurerm_public_ip.vm.ip_address}"
}

output "grupo_recursos" {
  description = "Grupo de recursos que `terraform destroy` borra completo."
  value       = azurerm_resource_group.lowtide.name
}

output "identidad_principal_id" {
  description = "principalId de la identidad de la VM, por si se le da otro rol (respaldo, llaves) como a vm-lowtide."
  value       = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}

output "con_tunel" {
  description = "true si la VM levanta cloudflared con el token de Key Vault."
  value       = local.con_tunel
}

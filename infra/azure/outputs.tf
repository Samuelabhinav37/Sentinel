output "elastic_public_ip" {
  value = module.elastic_vm.public_ip
}

output "wazuh_public_ip" {
  value = module.wazuh_vm.public_ip
}

output "soar_public_ip" {
  value = module.soar_vm.public_ip
}

output "target_public_ip" {
  description = "Public IP of the Azure Linux attack target (use tailscale ssh in practice)"
  value       = module.linux_target.public_ip
}

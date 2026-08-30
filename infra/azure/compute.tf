module "elastic_vm" {
  source = "../modules/instance-azure"

  resource_group_name = azurerm_resource_group.sentinel.name
  location            = var.location
  subnet_id           = azurerm_subnet.public.id
  ssh_public_key_path = var.ssh_public_key_path
  tailscale_authkey   = var.tailscale_authkey

  display_name = "sentinel-elastic"
  vm_size      = var.elastic_vm_size
  role         = "elastic"
}

module "wazuh_vm" {
  source = "../modules/instance-azure"

  resource_group_name = azurerm_resource_group.sentinel.name
  location            = var.location
  subnet_id           = azurerm_subnet.public.id
  ssh_public_key_path = var.ssh_public_key_path
  tailscale_authkey   = var.tailscale_authkey

  display_name = "sentinel-wazuh"
  vm_size      = var.wazuh_vm_size
  role         = "wazuh"
}

module "soar_vm" {
  source = "../modules/instance-azure"

  resource_group_name = azurerm_resource_group.sentinel.name
  location            = var.location
  subnet_id           = azurerm_subnet.public.id
  ssh_public_key_path = var.ssh_public_key_path
  tailscale_authkey   = var.tailscale_authkey

  display_name = "sentinel-soar"
  vm_size      = var.soar_vm_size
  role         = "soar"
}

# Lightweight Linux attack-target endpoint (not part of the stack). Enrolls into
# the live OCI Elastic over Tailscale via target.yaml.tftpl. Mirrors
# infra/aws/compute.tf's module "linux_target".
module "linux_target" {
  source = "../modules/instance-azure"

  resource_group_name = azurerm_resource_group.sentinel.name
  location            = var.location
  subnet_id           = azurerm_subnet.public.id
  ssh_public_key_path = var.ssh_public_key_path
  tailscale_authkey   = var.tailscale_authkey

  display_name     = "sentinel-target-azure"
  vm_size          = var.target_vm_size
  role             = "target"
  elastic_url      = var.elastic_url
  elastic_password = var.elastic_password
}

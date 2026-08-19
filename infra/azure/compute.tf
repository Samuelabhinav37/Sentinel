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

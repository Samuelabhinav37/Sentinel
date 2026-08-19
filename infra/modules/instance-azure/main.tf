# Azure equivalent of infra/modules/instance (OCI). Deliberately reuses that module's
# cloud-init template unmodified - cloud-init is provider-agnostic and both OCI and Azure
# accept it as instance user-data (custom_data here), so provisioning behavior stays
# identical across providers instead of being reimplemented per-cloud.
resource "azurerm_public_ip" "this" {
  name                = "${var.display_name}-pip"
  resource_group_name = var.resource_group_name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Role = var.role
  }
}

resource "azurerm_network_interface" "this" {
  name                = "${var.display_name}-nic"
  resource_group_name = var.resource_group_name
  location            = var.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.this.id
  }
}

resource "azurerm_linux_virtual_machine" "this" {
  name                = var.display_name
  resource_group_name = var.resource_group_name
  location            = var.location
  size                = var.vm_size
  admin_username      = var.admin_username

  network_interface_ids = [azurerm_network_interface.this.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  custom_data = base64encode(templatefile(
    "${path.module}/../instance/cloud-init/base.yaml.tftpl",
    {
      tailscale_authkey = var.tailscale_authkey
      role              = var.role
    }
  ))

  tags = {
    Role = var.role
  }

  # Same reasoning as modules/instance/main.tf: cloud-init only runs once at first boot.
  # Don't let a template edit touch a running instance's custom_data.
  lifecycle {
    ignore_changes = [custom_data]
  }
}

output "public_ip" {
  value = azurerm_public_ip.this.ip_address
}

output "id" {
  value = azurerm_linux_virtual_machine.this.id
}

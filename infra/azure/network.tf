# Mirrors infra/network.tf's (OCI) exact ingress posture: only SSH and Tailscale reach
# any instance from the public internet. Kibana, the Wazuh dashboard, Shuffle, and n8n
# stay reachable only over the Tailscale mesh, same design decision as the OCI side.
#
# One deliberate deviation: Azure NSG rules can't filter ICMP by type/code the way OCI's
# security lists and AWS's security groups do - protocol "Icmp" allows all ICMP types.
# The OCI/AWS roots scope this to path-MTU-discovery only (type 3); Azure's rule is
# slightly broader by construction. Documented, not silently accepted - see docs/multi-cloud.md.
resource "azurerm_resource_group" "sentinel" {
  name     = "sentinel"
  location = var.location
}

resource "azurerm_virtual_network" "sentinel" {
  name                = "sentinel-vnet"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
}

resource "azurerm_subnet" "public" {
  name                 = "sentinel-public-subnet"
  resource_group_name  = azurerm_resource_group.sentinel.name
  virtual_network_name = azurerm_virtual_network.sentinel.name
  address_prefixes     = [var.public_subnet_cidr]
}

resource "azurerm_network_security_group" "public" {
  name                = "sentinel-public-nsg"
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name

  security_rule {
    name                       = "SSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Tailscale"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "41641"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "IcmpPathMtuDiscovery"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Icmp"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "public" {
  subnet_id                 = azurerm_subnet.public.id
  network_security_group_id = azurerm_network_security_group.public.id
}

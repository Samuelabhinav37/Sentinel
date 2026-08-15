resource "oci_core_vcn" "sentinel" {
  compartment_id = var.compartment_ocid
  cidr_block     = var.vcn_cidr
  display_name   = "sentinel-vcn"
  dns_label      = "sentinel"
}

resource "oci_core_internet_gateway" "sentinel" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.sentinel.id
  display_name   = "sentinel-igw"
  enabled        = true
}

resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.sentinel.id
  display_name   = "sentinel-public-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_internet_gateway.sentinel.id
  }
}

# Mirrors the manually-configured security list from the original click-ops setup:
# only SSH and Tailscale are reachable from the public internet. Kibana, the Wazuh
# dashboard, Shuffle, and n8n are only reachable over the Tailscale mesh.
resource "oci_core_security_list" "public" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.sentinel.id
  display_name   = "sentinel-public-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    protocol = "6" # TCP
    source   = "0.0.0.0/0"
    tcp_options {
      min = 22
      max = 22
    }
    description = "SSH"
  }

  ingress_security_rules {
    protocol = "17" # UDP
    source   = "0.0.0.0/0"
    udp_options {
      min = 41641
      max = 41641
    }
    description = "Tailscale"
  }

  ingress_security_rules {
    protocol = "1" # ICMP
    source   = "0.0.0.0/0"
    icmp_options {
      type = 3
      code = 4
    }
    description = "Path MTU discovery"
  }

  ingress_security_rules {
    protocol = "1" # ICMP
    source   = var.vcn_cidr
    icmp_options {
      type = 3
    }
    description = "Destination unreachable within VCN"
  }
}

resource "oci_core_subnet" "public" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_vcn.sentinel.id
  cidr_block                 = var.public_subnet_cidr
  display_name               = "sentinel-public-subnet"
  dns_label                  = "public"
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.public.id]
  prohibit_public_ip_on_vnic = false
}

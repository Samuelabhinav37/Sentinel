data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

data "oci_core_images" "ubuntu" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  shape                    = "VM.Standard.E4.Flex"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

locals {
  ad = data.oci_identity_availability_domains.ads.availability_domains[0].name
}

module "elastic_vm" {
  source = "./modules/instance"

  compartment_ocid    = var.compartment_ocid
  availability_domain = local.ad
  subnet_id            = oci_core_subnet.public.id
  image_id             = data.oci_core_images.ubuntu.images[0].id
  ssh_public_key_path  = var.ssh_public_key_path
  tailscale_authkey    = var.tailscale_authkey

  display_name = "sentinel-elastic"
  ocpus        = var.elastic_ocpus
  memory_gb    = var.elastic_memory_gb
  role         = "elastic"
}

module "wazuh_vm" {
  source = "./modules/instance"

  compartment_ocid    = var.compartment_ocid
  availability_domain = local.ad
  subnet_id            = oci_core_subnet.public.id
  image_id             = data.oci_core_images.ubuntu.images[0].id
  ssh_public_key_path  = var.ssh_public_key_path
  tailscale_authkey    = var.tailscale_authkey

  display_name = "sentinel-wazuh"
  ocpus        = var.wazuh_ocpus
  memory_gb    = var.wazuh_memory_gb
  role         = "wazuh"
}

module "soar_vm" {
  source = "./modules/instance"

  compartment_ocid    = var.compartment_ocid
  availability_domain = local.ad
  subnet_id            = oci_core_subnet.public.id
  image_id             = data.oci_core_images.ubuntu.images[0].id
  ssh_public_key_path  = var.ssh_public_key_path
  tailscale_authkey    = var.tailscale_authkey

  display_name = "sentinel-soar"
  ocpus        = var.soar_ocpus
  memory_gb    = var.soar_memory_gb
  role         = "soar"
}

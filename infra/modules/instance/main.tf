resource "oci_core_instance" "this" {
  compartment_id      = var.compartment_ocid
  availability_domain = var.availability_domain
  display_name        = var.display_name
  shape                = "VM.Standard.E4.Flex"

  shape_config {
    ocpus         = var.ocpus
    memory_in_gbs = var.memory_gb
  }

  create_vnic_details {
    subnet_id        = var.subnet_id
    assign_public_ip = true
  }

  source_details {
    source_type = "image"
    source_id   = var.image_id
  }

  metadata = {
    ssh_authorized_keys = file(var.ssh_public_key_path)
    user_data = base64encode(templatefile(
      "${path.module}/cloud-init/base.yaml.tftpl",
      {
        tailscale_authkey = var.tailscale_authkey
        role               = var.role
      }
    ))
  }

  # user_data / cloud-init only runs once at first boot - OCI has no API to re-apply
  # it to a running instance, so the provider force-replaces the instance on any
  # change. Once an instance is live, edit it directly (SSH) instead of through
  # cloud-init; don't let template edits trigger a destroy of a running box.
  lifecycle {
    ignore_changes = [metadata]
  }
}

output "public_ip" {
  value = oci_core_instance.this.public_ip
}

output "id" {
  value = oci_core_instance.this.id
}

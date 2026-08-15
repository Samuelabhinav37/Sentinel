# Disposable Windows endpoint used only for Sysmon/Winlogbeat telemetry + Atomic Red
# Team emulation - not part of the core SOC stack. Reachable only over Tailscale
# (tailscale ssh), same as everything else in this project.

data "oci_core_images" "windows_target" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Windows"
  operating_system_version = "Server 2022 Standard"
  shape                    = "VM.Standard.E4.Flex"
  sort_by                  = "TIMECREATED"
  sort_order                = "DESC"
}

resource "oci_core_instance" "windows_target" {
  compartment_id      = var.compartment_ocid
  availability_domain = local.ad
  display_name        = "sentinel-win-target"
  shape                = "VM.Standard.E4.Flex"

  shape_config {
    ocpus         = 2
    memory_in_gbs = 8
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.public.id
    assign_public_ip = true
  }

  source_details {
    source_type = "image"
    source_id   = data.oci_core_images.windows_target.images[0].id
  }

  metadata = {
    user_data = base64encode(templatefile(
      "${path.module}/windows_target_userdata.ps1.tftpl",
      { tailscale_authkey = var.tailscale_authkey }
    ))
  }

  # Same reasoning as modules/instance/main.tf - user_data only runs once at first
  # boot, and OCI force-replaces the instance on any metadata change.
  lifecycle {
    ignore_changes = [metadata]
  }
}

output "windows_target_public_ip" {
  value = oci_core_instance.windows_target.public_ip
}

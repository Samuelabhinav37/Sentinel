# AWS equivalent of infra/modules/instance (OCI) and infra/modules/instance-azure.
# Reuses the same provider-agnostic cloud-init templates unmodified: base.yaml.tftpl
# for the stack roles, target.yaml.tftpl for a lightweight attack-target endpoint
# that also ships auditbeat to the live Elastic.
locals {
  user_data = var.role == "target" ? templatefile(
    "${path.module}/../instance/cloud-init/target.yaml.tftpl",
    {
      tailscale_authkey = var.tailscale_authkey
      role              = var.role
      hostname          = var.display_name
      elastic_url       = var.elastic_url
      elastic_password  = var.elastic_password
    }
    ) : templatefile(
    "${path.module}/../instance/cloud-init/base.yaml.tftpl",
    {
      tailscale_authkey = var.tailscale_authkey
      role              = var.role
    }
  )
}

resource "aws_key_pair" "this" {
  key_name   = var.display_name
  public_key = file(var.ssh_public_key_path)
}

resource "aws_instance" "this" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = var.security_group_ids
  key_name                    = aws_key_pair.this.key_name
  associate_public_ip_address = true
  user_data                   = local.user_data

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
  }

  tags = {
    Name = var.display_name
    Role = var.role
  }

  # Same reasoning as the OCI/Azure modules: cloud-init only runs once at first
  # boot. Don't let a template edit force-replace a running instance.
  lifecycle {
    ignore_changes = [user_data]
  }
}

output "public_ip" {
  value = aws_instance.this.public_ip
}

output "id" {
  value = aws_instance.this.id
}

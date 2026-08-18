# AWS equivalent of infra/modules/instance (OCI). Deliberately reuses that module's
# cloud-init template unmodified - cloud-init is provider-agnostic and both OCI and AWS
# accept it as user_data, so provisioning behavior stays identical across providers
# instead of being reimplemented per-cloud.
resource "aws_instance" "this" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  key_name               = var.key_name

  associate_public_ip_address = true

  tags = {
    Name = var.display_name
    Role = var.role
  }

  user_data = base64encode(templatefile(
    "${path.module}/../instance/cloud-init/base.yaml.tftpl",
    {
      tailscale_authkey = var.tailscale_authkey
      role               = var.role
    }
  ))

  # Same reasoning as modules/instance/main.tf: cloud-init only runs once at first boot.
  # Don't let a template edit touch a running instance's user_data.
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

# Canonical's official Ubuntu 22.04 LTS (jammy) HVM/EBS image - same OS the OCI
# and Azure Linux VMs run, so the shared cloud-init behaves identically.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

module "linux_target" {
  source = "../modules/instance-aws"

  subnet_id           = aws_subnet.public.id
  security_group_ids  = [aws_security_group.public.id]
  ami_id              = data.aws_ami.ubuntu.id
  instance_type       = var.target_instance_type
  ssh_public_key_path = var.ssh_public_key_path
  tailscale_authkey   = var.tailscale_authkey

  display_name     = "sentinel-target-aws"
  role             = "target"
  elastic_url      = var.elastic_url
  elastic_password = var.elastic_password
}

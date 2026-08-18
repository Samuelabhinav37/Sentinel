data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

resource "aws_key_pair" "sentinel" {
  key_name   = "sentinel"
  public_key = file(var.ssh_public_key_path)
}

module "elastic_vm" {
  source = "../modules/instance-aws"

  ami_id             = data.aws_ami.ubuntu.id
  subnet_id          = aws_subnet.public.id
  security_group_id  = aws_security_group.public.id
  key_name           = aws_key_pair.sentinel.key_name
  tailscale_authkey  = var.tailscale_authkey

  display_name  = "sentinel-elastic"
  instance_type = var.elastic_instance_type
  role          = "elastic"
}

module "wazuh_vm" {
  source = "../modules/instance-aws"

  ami_id             = data.aws_ami.ubuntu.id
  subnet_id          = aws_subnet.public.id
  security_group_id  = aws_security_group.public.id
  key_name           = aws_key_pair.sentinel.key_name
  tailscale_authkey  = var.tailscale_authkey

  display_name  = "sentinel-wazuh"
  instance_type = var.wazuh_instance_type
  role          = "wazuh"
}

module "soar_vm" {
  source = "../modules/instance-aws"

  ami_id             = data.aws_ami.ubuntu.id
  subnet_id          = aws_subnet.public.id
  security_group_id  = aws_security_group.public.id
  key_name           = aws_key_pair.sentinel.key_name
  tailscale_authkey  = var.tailscale_authkey

  display_name  = "sentinel-soar"
  instance_type = var.soar_instance_type
  role          = "soar"
}

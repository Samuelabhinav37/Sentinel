# Mirrors infra/network.tf's (OCI) exact ingress posture: only SSH and Tailscale reach
# any instance from the public internet. Kibana, the Wazuh dashboard, Shuffle, and n8n
# stay reachable only over the Tailscale mesh, same design decision as the OCI side.
resource "aws_vpc" "sentinel" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "sentinel-vpc"
  }
}

resource "aws_internet_gateway" "sentinel" {
  vpc_id = aws_vpc.sentinel.id

  tags = {
    Name = "sentinel-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.sentinel.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sentinel.id
  }

  tags = {
    Name = "sentinel-public-rt"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.sentinel.id
  cidr_block               = var.public_subnet_cidr
  availability_zone        = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch  = true

  tags = {
    Name = "sentinel-public-subnet"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "public" {
  name        = "sentinel-public-sg"
  description = "Only SSH and Tailscale reachable from the public internet"
  vpc_id      = aws_vpc.sentinel.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Tailscale"
    from_port   = 41641
    to_port     = 41641
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Path MTU discovery (fragmentation needed) - mirrors the OCI security list"
    from_port   = 3
    to_port     = 4
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sentinel-public-sg"
  }
}

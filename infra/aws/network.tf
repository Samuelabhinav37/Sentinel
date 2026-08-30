# Mirrors infra/network.tf (OCI) and infra/azure/network.tf: only SSH and
# Tailscale reach the instance from the public internet. All service UIs (Kibana,
# Wazuh dashboard, Shuffle, n8n) and the Elastic ingest endpoint are reachable
# only over the Tailscale mesh - same ingress posture as the other two roots.
#
# Unlike Azure's NSG, an AWS security group CAN scope ICMP by type/code, so the
# path-MTU-discovery rule here is narrowed to type 3 code 4 exactly as the OCI
# security list does. See docs/multi-cloud.md.
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

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.sentinel.id
  cidr_block              = var.public_subnet_cidr
  map_public_ip_on_launch = true

  tags = {
    Name = "sentinel-public-subnet"
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

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "public" {
  name        = "sentinel-public-sg"
  description = "SSH + Tailscale + PMTUD only; everything else rides the tailnet"
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
    description = "Path MTU discovery (ICMP type 3 code 4)"
    from_port   = 3
    to_port     = 4
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sentinel-public-sg"
  }
}

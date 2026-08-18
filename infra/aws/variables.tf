variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "ssh_public_key_path" {
  type        = string
  description = "Path to the SSH public key installed on every instance"
  default     = "~/.ssh/id_ed25519.pub"
}

variable "tailscale_authkey" {
  type        = string
  description = "Tailscale auth key (reusable, ephemeral recommended) used by cloud-init to join the tailnet"
  sensitive   = true
}

# --- Network ---
variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.0.1.0/24"
}

# --- Compute sizing. Approximate AWS equivalents of the OCI root's default sizing
# (infra/variables.tf: elastic 4 ocpu/32GB, wazuh/soar 2 ocpu/16GB each) - adjust freely,
# these aren't required to match exactly. ---
variable "elastic_instance_type" {
  type    = string
  default = "r5.xlarge" # 4 vCPU / 32 GiB
}

variable "wazuh_instance_type" {
  type    = string
  default = "t3.xlarge" # 4 vCPU / 16 GiB
}

variable "soar_instance_type" {
  type    = string
  default = "t3.xlarge" # 4 vCPU / 16 GiB
}

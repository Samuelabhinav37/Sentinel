variable "region" {
  type    = string
  default = "us-east-1"
}

variable "ssh_public_key_path" {
  type        = string
  description = "Path to the SSH public key installed on the attack-target instance"
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
  default = "10.2.0.0/16" # OCI uses 10.0/16, Azure 10.1/16, AWS 10.2/16
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.2.1.0/24"
}

# --- Compute ---
variable "target_instance_type" {
  type    = string
  default = "t3.small" # 2 vCPU / 2 GiB - enough for one auditbeat container
}

# --- Elastic enrolment. The attack target ships auditbeat straight to the live
# OCI Elastic over Tailscale (MagicDNS name or tailnet IP). elastic_password is
# the elastic superuser credential from infra/compose/elastic/.env; it lives only
# in the gitignored terraform.tfvars, never here. ---
variable "elastic_url" {
  type      = string
  sensitive = true
}

variable "elastic_password" {
  type      = string
  sensitive = true
}

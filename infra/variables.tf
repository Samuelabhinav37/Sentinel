# --- OCI API auth (see infra/terraform.tfvars.example) ---
variable "tenancy_ocid" {
  type = string
}

variable "user_ocid" {
  type = string
}

variable "fingerprint" {
  type = string
}

variable "private_key_path" {
  type = string
}

variable "region" {
  type    = string
  default = "us-ashburn-1"
}

variable "compartment_ocid" {
  type        = string
  description = "Compartment to create Sentinel resources in (root compartment OCID works for a personal free-tier tenancy)"
}

# --- Access ---
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
variable "vcn_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.0.1.0/24"
}

# --- Compute sizing (must stay within the Always Free Ampere A1 budget: 4 OCPU / 24GB total) ---
variable "elastic_ocpus" {
  type    = number
  default = 2
}

variable "elastic_memory_gb" {
  type    = number
  default = 12
}

variable "wazuh_ocpus" {
  type    = number
  default = 1
}

variable "wazuh_memory_gb" {
  type    = number
  default = 6
}

variable "soar_ocpus" {
  type    = number
  default = 1
}

variable "soar_memory_gb" {
  type    = number
  default = 6
}

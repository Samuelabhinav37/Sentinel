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

# --- Windows telemetry target (see infra/windows_target.tf) ---
variable "elastic_url" {
  type        = string
  description = "Elasticsearch URL (Tailscale address, e.g. https://100.x.x.x:9200) that Winlogbeat on the Windows target ships to"
  sensitive   = true
}

variable "elastic_password" {
  type        = string
  description = "Password for the elastic superuser, used by Winlogbeat on the Windows target — same credential auditbeat already uses (infra/compose/wazuh/auditbeat)"
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

# --- Compute sizing (VM.Standard.E4.Flex, paid via trial credit — not Always Free eligible) ---
variable "elastic_ocpus" {
  type    = number
  default = 4
}

variable "elastic_memory_gb" {
  type    = number
  default = 32
}

variable "wazuh_ocpus" {
  type    = number
  default = 2
}

variable "wazuh_memory_gb" {
  type    = number
  default = 16
}

variable "soar_ocpus" {
  type    = number
  default = 2
}

variable "soar_memory_gb" {
  type    = number
  default = 16
}

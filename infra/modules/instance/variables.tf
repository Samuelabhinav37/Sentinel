variable "compartment_ocid" {
  type = string
}

variable "availability_domain" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "image_id" {
  type = string
}

variable "ssh_public_key_path" {
  type = string
}

variable "tailscale_authkey" {
  type      = string
  sensitive = true
}

variable "display_name" {
  type = string
}

variable "ocpus" {
  type = number
}

variable "memory_gb" {
  type = number
}

variable "role" {
  type        = string
  description = "elastic | wazuh | soar - selects which cloud-init template to render"
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "vm_size" {
  type = string
}

variable "admin_username" {
  type    = string
  default = "sentinel"
}

variable "ssh_public_key_path" {
  type        = string
  description = "Path to the SSH public key installed on the instance"
}

variable "tailscale_authkey" {
  type      = string
  sensitive = true
}

variable "display_name" {
  type = string
}

variable "role" {
  type        = string
  description = "elastic | wazuh | soar | target - selects which cloud-init template to render"
}

# Only consumed by target.yaml.tftpl (role == "target"). Empty defaults so the
# elastic/wazuh/soar modules don't have to supply them.
variable "elastic_url" {
  type      = string
  sensitive = true
  default   = ""
}

variable "elastic_password" {
  type      = string
  sensitive = true
  default   = ""
}

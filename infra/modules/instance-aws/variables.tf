variable "subnet_id" {
  type = string
}

variable "security_group_ids" {
  type = list(string)
}

variable "instance_type" {
  type = string
}

variable "ami_id" {
  type = string
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
  description = "target | elastic | wazuh | soar - selects which cloud-init template to render"
}

# Only consumed by target.yaml.tftpl (role == \"target\"). Left with empty
# defaults so the base.yaml.tftpl roles don't have to supply them.
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

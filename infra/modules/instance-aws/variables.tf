variable "ami_id" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "security_group_id" {
  type = string
}

variable "key_name" {
  type        = string
  description = "Name of an existing aws_key_pair (created once in infra/aws/compute.tf and shared across all three instances)"
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
  description = "elastic | wazuh | soar - selects which cloud-init template to render"
}

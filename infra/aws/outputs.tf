output "target_public_ip" {
  description = "Public IP of the AWS Linux attack target (SSH only; use tailscale ssh in practice)"
  value       = module.linux_target.public_ip
}

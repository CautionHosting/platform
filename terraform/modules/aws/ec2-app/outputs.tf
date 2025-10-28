# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.app.id
}

output "public_ip" {
  description = "Public IP address of the instance"
  value       = aws_eip.app.public_ip
}

output "public_dns" {
  description = "Public DNS name of the instance"
  value       = aws_eip.app.public_dns
}

output "url" {
  description = "Application URL"
  value       = "http://${aws_eip.app.public_ip}:${var.app_port}"
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.app.id
}

output "resource_id" {
  description = "Resource ID (passed through)"
  value       = var.resource_id
}

output "resource_name" {
  description = "Resource name (passed through)"
  value       = var.resource_name
}

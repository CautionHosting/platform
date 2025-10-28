# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

output "public_ip" {
  description = "Public IP address of the enclave instance"
  value       = aws_eip.enclave.public_ip
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.enclave.id
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.enclave.id
}

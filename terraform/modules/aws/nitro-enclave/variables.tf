# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

variable "resource_id" {
  description = "Database ID of the compute resource"
  type        = string
}

variable "resource_name" {
  description = "Name of the resource (used for tagging)"
  type        = string
}

variable "org_id" {
  description = "Organization UUID"
  type        = string
}

variable "ami_id" {
  description = "AMI ID for Amazon Linux 2023 with nitro-cli"
  type        = string
}

variable "instance_type" {
  description = "Instance type (must be Nitro-enabled: m5.xlarge, c5.xlarge, etc.)"
  type        = string
  default     = "m5.xlarge"
}

variable "volume_size_gb" {
  description = "Root volume size in GB"
  type        = number
  default     = 20
}

variable "eif_s3_path" {
  description = "S3 path to the EIF file (s3://bucket/path/to/file.eif)"
  type        = string
}

variable "memory_mb" {
  description = "Memory allocation for the enclave in MB"
  type        = number
  default     = 1024
}

variable "cpu_count" {
  description = "Number of CPUs to allocate to the enclave"
  type        = number
  default     = 2
}

variable "debug_mode" {
  description = "Enable debug console for the enclave"
  type        = bool
  default     = false
}

variable "ssh_key_name" {
  description = "Name of the EC2 key pair for SSH access (optional)"
  type        = string
  default     = ""
}

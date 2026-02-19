# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-west-2"
}

variable "state_bucket_name" {
  description = "Name of the S3 bucket for Terraform state (must be globally unique)"
  type        = string
  default     = "caution-terraform-state"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.state_bucket_name))
    error_message = "Bucket name must be lowercase alphanumeric with hyphens"
  }
}

variable "eif_bucket_name" {
  description = "Name of the S3 bucket for enclave image storage (must be globally unique)"
  type        = string
  default     = "caution-eif-storage"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.eif_bucket_name))
    error_message = "Bucket name must be lowercase alphanumeric with hyphens"
  }
}

variable "lock_table_name" {
  description = "Name of the DynamoDB table for state locking"
  type        = string
  default     = "terraform-state-lock"
}

variable "service_user_name" {
  description = "Name of the IAM user for the platform"
  type        = string
  default     = "caution-platform"
}

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

variable "builder_vpc_id" {
  description = "Optional VPC ID for builder subnet validation. If omitted, bootstrap derives the VPC from builder_subnet_id."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.builder_vpc_id == null ||
      (
        trimspace(var.builder_vpc_id) != "" &&
        var.builder_subnet_id != null &&
        trimspace(var.builder_subnet_id) != ""
      )
    )
    error_message = "builder_vpc_id can only be set when builder_subnet_id is also set."
  }
}

variable "builder_subnet_id" {
  description = "Existing subnet ID to use for dedicated builders. If unset, bootstrap falls back to the default VPC and its first public subnet."
  type        = string
  default     = null
  nullable    = true
}

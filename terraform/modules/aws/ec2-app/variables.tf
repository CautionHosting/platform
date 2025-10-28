# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

variable "org_id" {
  description = "Organization ID"
  type        = string
}

variable "resource_id" {
  description = "Resource ID from database"
  type        = string
}

variable "resource_name" {
  description = "Resource name (e.g., resource-415af99a)"
  type        = string
}

variable "ami_id" {
  description = "AMI ID containing the pre-built application image"
  type        = string
}

variable "app_port" {
  description = "Port the application listens on"
  type        = number
  default     = 8080
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "volume_size_gb" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 30
}

variable "vpc_id" {
  description = "VPC ID to deploy into (use default VPC)"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID to deploy into (use default subnet)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}


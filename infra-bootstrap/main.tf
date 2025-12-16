# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_s3_bucket" "terraform_state" {
  bucket = var.state_bucket_name
  
  tags = {
    Name        = "Terraform State Storage"
    Purpose     = "terraform-state"
    ManagedBy   = "infra-bootstrap"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "terraform_state_lock" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }
  
  tags = {
    Name      = "Terraform State Lock"
    Purpose   = "terraform-state-lock"
    ManagedBy = "infra-bootstrap"
  }
}

resource "aws_iam_user" "terraform_service" {
  name = var.service_user_name
  
  tags = {
    Purpose   = "terraform-automation"
    ManagedBy = "infra-bootstrap"
  }
}

data "aws_iam_policy_document" "terraform_service" {
  statement {
    sid = "AllowOrganizationAccountCreation"
    actions = [
      "organizations:CreateAccount",
      "organizations:DescribeCreateAccountStatus",
      "organizations:DescribeAccount",
      "organizations:DescribeOrganization",
      "organizations:ListAccounts"
    ]
    resources = ["*"]
  }

  statement {
    sid = "AllowTerraformStateManagement"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.terraform_state.arn,
      "${aws_s3_bucket.terraform_state.arn}/*"
    ]
  }

  statement {
    sid = "AllowStateLocking"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
      "dynamodb:DescribeTable"
    ]
    resources = [aws_dynamodb_table.terraform_state_lock.arn]
  }
}

resource "aws_iam_user_policy" "terraform_service" {
  name   = "TerraformOrganizationAccess"
  user   = aws_iam_user.terraform_service.name
  policy = data.aws_iam_policy_document.terraform_service.json
}

resource "aws_iam_access_key" "terraform_service" {
  user = aws_iam_user.terraform_service.name
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for Terraform state"
  value       = aws_s3_bucket.terraform_state.id
}

output "dynamodb_table_name" {
  description = "Name of the DynamoDB table for state locking"
  value       = aws_dynamodb_table.terraform_state_lock.id
}

output "iam_user_name" {
  description = "Name of the IAM user for Terraform service"
  value       = aws_iam_user.terraform_service.name
}

output "aws_access_key_id" {
  description = "AWS Access Key ID (store securely!)"
  value       = aws_iam_access_key.terraform_service.id
  sensitive   = true
}

output "aws_secret_access_key" {
  description = "AWS Secret Access Key (store securely!)"
  value       = aws_iam_access_key.terraform_service.secret
  sensitive   = true
}

output "configuration_summary" {
  description = "Summary of created resources"
  value = {
    s3_bucket        = aws_s3_bucket.terraform_state.id
    dynamodb_table   = aws_dynamodb_table.terraform_state_lock.id
    iam_user         = aws_iam_user.terraform_service.name
    region           = var.aws_region
  }
}

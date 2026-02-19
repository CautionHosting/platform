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

data "aws_caller_identity" "current" {}

# --- S3: Terraform state ---

resource "aws_s3_bucket" "terraform_state" {
  bucket = var.state_bucket_name

  tags = {
    Name      = "Terraform State Storage"
    Purpose   = "terraform-state"
    ManagedBy = "infra-bootstrap"
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

# --- S3: EIF storage ---

resource "aws_s3_bucket" "eif_storage" {
  bucket = var.eif_bucket_name

  tags = {
    Name      = "Enclave Image Storage"
    Purpose   = "eif-storage"
    ManagedBy = "infra-bootstrap"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "eif_storage" {
  bucket = aws_s3_bucket.eif_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "eif_storage" {
  bucket = aws_s3_bucket.eif_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- DynamoDB: Terraform state locking ---

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

# --- IAM: Platform service user ---

resource "aws_iam_user" "platform" {
  name = var.service_user_name

  tags = {
    Purpose   = "caution-platform"
    ManagedBy = "infra-bootstrap"
  }
}

resource "aws_iam_access_key" "platform" {
  user = aws_iam_user.platform.name
}

resource "aws_iam_policy" "platform_deploy" {
  name        = "CautionPlatformDeploy"
  description = "Scoped permissions for the Caution platform to manage infrastructure"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EC2"
        Effect   = "Allow"
        Action   = "ec2:*"
        Resource = "*"
      },
      {
        Sid    = "STS"
        Effect = "Allow"
        Action = ["sts:GetCallerIdentity"]
        Resource = "*"
      },
      {
        Sid    = "ManageEnclaveRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:PassRole",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:ListInstanceProfilesForRole",
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/enclave-*"
      },
      {
        Sid    = "ManageEnclaveInstanceProfiles"
        Effect = "Allow"
        Action = [
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:GetInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:TagInstanceProfile",
          "iam:UntagInstanceProfile",
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/enclave-*"
      },
      {
        Sid    = "S3EIF"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject",
        ]
        Resource = [
          aws_s3_bucket.eif_storage.arn,
          "${aws_s3_bucket.eif_storage.arn}/*",
        ]
      },
      {
        Sid    = "S3TerraformState"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject",
        ]
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*",
        ]
      },
      {
        Sid    = "DynamoDBStateLock"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DescribeTable",
          "dynamodb:DeleteItem",
        ]
        Resource = aws_dynamodb_table.terraform_state_lock.arn
      },
    ]
  })
}

resource "aws_iam_user_policy_attachment" "platform" {
  user       = aws_iam_user.platform.name
  policy_arn = aws_iam_policy.platform_deploy.arn
}

# --- Outputs ---

output "s3_bucket_name" {
  description = "Name of the S3 bucket for Terraform state"
  value       = aws_s3_bucket.terraform_state.id
}

output "eif_bucket_name" {
  description = "Name of the S3 bucket for EIF storage"
  value       = aws_s3_bucket.eif_storage.id
}

output "dynamodb_table_name" {
  description = "Name of the DynamoDB table for state locking"
  value       = aws_dynamodb_table.terraform_state_lock.id
}

output "iam_user_name" {
  description = "Name of the IAM user"
  value       = aws_iam_user.platform.name
}

output "policy_arn" {
  description = "ARN of the deploy policy"
  value       = aws_iam_policy.platform_deploy.arn
}

output "aws_access_key_id" {
  description = "AWS Access Key ID — put in .env as AWS_ACCESS_KEY_ID"
  value       = aws_iam_access_key.platform.id
  sensitive   = true
}

output "aws_secret_access_key" {
  description = "AWS Secret Access Key — put in .env as AWS_SECRET_ACCESS_KEY"
  value       = aws_iam_access_key.platform.secret
  sensitive   = true
}

output "account_id" {
  description = "AWS Account ID — put in .env as AWS_ACCOUNT_ID"
  value       = data.aws_caller_identity.current.account_id
}

output "configuration_summary" {
  description = "Summary of created resources"
  value = {
    s3_state_bucket  = aws_s3_bucket.terraform_state.id
    s3_eif_bucket    = aws_s3_bucket.eif_storage.id
    dynamodb_table   = aws_dynamodb_table.terraform_state_lock.id
    iam_user         = aws_iam_user.platform.name
    account_id       = data.aws_caller_identity.current.account_id
    region           = var.aws_region
  }
}

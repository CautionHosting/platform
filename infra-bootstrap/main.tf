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

resource "aws_s3_bucket_versioning" "eif_storage" {
  bucket = aws_s3_bucket.eif_storage.id

  versioning_configuration {
    status = "Enabled"
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
        Sid    = "EC2Read"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2Manage"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:StopInstances",
          "ec2:StartInstances",
          "ec2:CreateVpc",
          "ec2:DeleteVpc",
          "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:ModifySubnetAttribute",
          "ec2:CreateInternetGateway",
          "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          "ec2:CreateRouteTable",
          "ec2:DeleteRouteTable",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:AssociateRouteTable",
          "ec2:DisassociateRouteTable",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:AllocateAddress",
          "ec2:ReleaseAddress",
          "ec2:AssociateAddress",
          "ec2:DisassociateAddress",
          "ec2:CreateTags",
          "ec2:DeleteTags",
        ]
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
          "s3:PutObjectTagging",
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

# --- Dedicated Builder: IAM Role + Instance Profile + Security Group ---

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "map-public-ip-on-launch"
    values = ["true"]
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_security_group" "builder" {
  name_prefix = "caution-builder-"
  description = "Caution dedicated builder instances (egress only)"
  vpc_id      = data.aws_vpc.default.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound (Docker pulls, S3)"
  }

  tags = {
    Name      = "caution-builder"
    ManagedBy = "infra-bootstrap"
  }
}

resource "aws_iam_role" "builder" {
  name = "caution-builder"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = {
    Name      = "caution-builder"
    ManagedBy = "infra-bootstrap"
  }
}

resource "aws_iam_role_policy" "builder_s3" {
  name = "caution-builder-s3"
  role = aws_iam_role.builder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:ListBucket",
      ]
      Resource = [
        aws_s3_bucket.eif_storage.arn,
        "${aws_s3_bucket.eif_storage.arn}/*",
      ]
    }]
  })
}

resource "aws_iam_instance_profile" "builder" {
  name = "caution-builder"
  role = aws_iam_role.builder.name

  tags = {
    Name      = "caution-builder"
    ManagedBy = "infra-bootstrap"
  }
}

# Also grant the platform user permission to pass the builder role and manage builder instances
resource "aws_iam_user_policy" "platform_builder" {
  name = "CautionPlatformBuilder"
  user = aws_iam_user.platform.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PassBuilderRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.builder.arn
      },
    ]
  })
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

output "builder_ami_id" {
  description = "Amazon Linux 2023 AMI ID for builders — put in .env as BUILDER_AMI_ID"
  value       = data.aws_ami.al2023.id
}

output "builder_security_group_id" {
  description = "Builder security group ID — put in .env as BUILDER_SECURITY_GROUP_ID"
  value       = aws_security_group.builder.id
}

output "builder_instance_profile" {
  description = "Builder instance profile name — put in .env as BUILDER_INSTANCE_PROFILE"
  value       = aws_iam_instance_profile.builder.name
}

output "builder_subnet_id" {
  description = "Default VPC public subnet for builders — put in .env as BUILDER_SUBNET_ID"
  value       = data.aws_subnets.public.ids[0]
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
    builder_ami      = data.aws_ami.al2023.id
    builder_sg       = aws_security_group.builder.id
    builder_profile  = aws_iam_instance_profile.builder.name
    builder_subnet   = data.aws_subnets.public.ids[0]
  }
}

# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

resource "aws_security_group" "app" {
  name_prefix = "app-${var.resource_name}-"
  description = "Security group for ${var.resource_name}"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTP"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS"
  }

  dynamic "ingress" {
    for_each = var.app_port != 80 && var.app_port != 443 ? [1] : []
    content {
      from_port   = var.app_port
      to_port     = var.app_port
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "Allow app port ${var.app_port}"
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name         = "app-${var.resource_name}"
    ResourceId   = var.resource_id
    ResourceName = var.resource_name
    OrgId        = var.org_id
    ManagedBy    = "terraform"
  }
}

resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = var.instance_type

  vpc_security_group_ids = [aws_security_group.app.id]
  subnet_id              = var.subnet_id
  
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  
  root_block_device {
    volume_size           = var.volume_size_gb
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  tags = {
    Name         = var.resource_name
    ResourceId   = var.resource_id
    ResourceName = var.resource_name
    OrgId        = var.org_id
    ManagedBy    = "terraform"
  }
}

resource "aws_eip" "app" {
  domain   = "vpc"
  instance = aws_instance.app.id

  tags = {
    Name         = "app-${var.resource_name}"
    ResourceId   = var.resource_id
    ResourceName = var.resource_name
    OrgId        = var.org_id
    ManagedBy    = "terraform"
  }
}

# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

resource "aws_vpc" "enclave" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name         = "vpc-${var.resource_name}"
    ResourceId   = var.resource_id
    ResourceName = var.resource_name
    OrgId        = var.org_id
    ManagedBy    = "terraform"
  }
}

resource "aws_internet_gateway" "enclave" {
  vpc_id = aws_vpc.enclave.id

  tags = {
    Name         = "igw-${var.resource_name}"
    ResourceId   = var.resource_id
    ResourceName = var.resource_name
    OrgId        = var.org_id
    ManagedBy    = "terraform"
  }
}

resource "aws_subnet" "enclave" {
  vpc_id                  = aws_vpc.enclave.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {
    Name         = "subnet-${var.resource_name}"
    ResourceId   = var.resource_id
    ResourceName = var.resource_name
    OrgId        = var.org_id
    ManagedBy    = "terraform"
  }
}

resource "aws_route_table" "enclave" {
  vpc_id = aws_vpc.enclave.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.enclave.id
  }

  tags = {
    Name         = "rt-${var.resource_name}"
    ResourceId   = var.resource_id
    ResourceName = var.resource_name
    OrgId        = var.org_id
    ManagedBy    = "terraform"
  }
}

resource "aws_route_table_association" "enclave" {
  subnet_id      = aws_subnet.enclave.id
  route_table_id = aws_route_table.enclave.id
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_security_group" "enclave" {
  name_prefix = "enclave-${var.resource_name}-"
  description = "Security group for ${var.resource_name} Nitro Enclave"
  vpc_id      = aws_vpc.enclave.id

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow app port"
  }

  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow attestation port"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow SSH for debugging"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name         = "enclave-${var.resource_name}"
    ResourceId   = var.resource_id
    ResourceName = var.resource_name
    OrgId        = var.org_id
    ManagedBy    = "terraform"
  }
}

resource "aws_instance" "enclave" {
  ami           = var.ami_id
  instance_type = var.instance_type

  vpc_security_group_ids = [aws_security_group.enclave.id]
  subnet_id              = aws_subnet.enclave.id

  key_name = var.ssh_key_name != "" ? var.ssh_key_name : null

  enclave_options {
    enabled = true
  }

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

  user_data = base64encode(templatefile("${path.module}/user-data.sh", {
    eif_s3_path = var.eif_s3_path
    memory_mb   = var.memory_mb
    cpu_count   = var.cpu_count
    debug_mode  = var.debug_mode
  }))

  tags = {
    Name         = var.resource_name
    ResourceId   = var.resource_id
    ResourceName = var.resource_name
    OrgId        = var.org_id
    ManagedBy    = "terraform"
  }
}

resource "aws_eip" "enclave" {
  domain   = "vpc"
  instance = aws_instance.enclave.id

  tags = {
    Name         = "enclave-${var.resource_name}"
    ResourceId   = var.resource_id
    ResourceName = var.resource_name
    OrgId        = var.org_id
    ManagedBy    = "terraform"
  }
}

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"

  default_tags {
    tags = {
      org_id = "00000000-0000-0000-0000-000000000000"
      ManagedBy = "caution+tofu"
    }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ec2_instance_type_offerings" "enclave" {
  location_type = "availability-zone"

  filter {
    name = "instance-type"
    values = [
      "m5.xlarge"
    ]
  }

  filter {
    name = "location"
    values = data.aws_availability_zones.available.names
  }
}

resource "aws_iam_role" "enclave" {
  name_prefix = "enclave-00000000-"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" } }] })
  tags = {
    Name = "enclave-role-00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
  }
}

resource "aws_iam_role_policy" "enclave_s3" {
  name_prefix = "enclave-s3-00000000-"
  role = aws_iam_role.enclave.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::caution-eif-storage-123456789012/eifs/00000000-0000-0000-0000-000000000000/*"] }] })
}

resource "aws_iam_instance_profile" "enclave" {
  name_prefix = "enclave-00000000-"
  role = aws_iam_role.enclave.name
  tags = {
    Name = "enclave-profile-00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
  }
}

resource "aws_vpc" "enclave" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  tags = {
    Name = "vpc-00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
  }
}

resource "aws_internet_gateway" "enclave" {
  vpc_id = aws_vpc.enclave.id
  tags = {
    Name = "igw-00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
  }
}

resource "aws_subnet" "enclave" {
  vpc_id = aws_vpc.enclave.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone = sort(data.aws_ec2_instance_type_offerings.enclave.locations)[0]
  tags = {
    Name = "subnet-00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
  }
}

resource "aws_route_table" "enclave" {
  vpc_id = aws_vpc.enclave.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.enclave.id
  }

  tags = {
    Name = "rt-00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
  }
}

resource "aws_route_table_association" "enclave" {
  subnet_id = aws_subnet.enclave.id
  route_table_id = aws_route_table.enclave.id
}

resource "aws_eip" "enclave" {
  domain = "vpc"
  tags = {
    Name = "enclave-00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
  }
}

output "vpc_id" {
  value = aws_vpc.enclave.id
}

output "subnet_id" {
  value = aws_subnet.enclave.id
}

output "availability_zone" {
  value = aws_subnet.enclave.availability_zone
}

output "instance_profile_name" {
  value = aws_iam_instance_profile.enclave.name
}

output "eip_allocation_id" {
  value = aws_eip.enclave.allocation_id
}

output "eip_public_ip" {
  value = aws_eip.enclave.public_ip
}

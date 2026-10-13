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

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners = [
    "amazon"
  ]

  filter {
    name = "name"
    values = [
      "al2023-ami-*-x86_64"
    ]
  }

  filter {
    name = "virtualization-type"
    values = [
      "hvm"
    ]
  }

  filter {
    name = "root-device-type"
    values = [
      "ebs"
    ]
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

variable "ports" {
  type = list(number)
  default = []
}

variable "http_port" {
  type = number
  default = 0
}

resource "aws_security_group" "enclave" {
  name_prefix = "enclave-00000000-"
  description = "Security group for 00000000-0000-0000-0000-000000000000 Nitro Enclave"
  vpc_id = aws_vpc.enclave.id

  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
    description = "Allow SSH"
  }

  ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
    description = "Allow HTTP"
  }

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
    description = "Allow HTTPS"
  }

  ingress {
    from_port = 49500
    to_port = 49500
    protocol = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
    description = "Allow STEVE encrypted transport"
  }

  ingress {
    from_port = 49504
    to_port = 49504
    protocol = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
    description = "Allow Locksmith shard receiver"
  }

  dynamic "ingress" {
    for_each = var.ports

    content {
      from_port = ingress.value
      to_port = ingress.value
      protocol = "tcp"
      cidr_blocks = [
        "0.0.0.0/0"
      ]
      description = "Allow user port ${ingress.value}"
    }
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
    description = "Allow all outbound"
  }

  tags = {
    Name = "enclave-00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
  }
}

resource "aws_instance" "enclave" {
  ami = data.aws_ami.amazon_linux_2023.id
  instance_type = "m5.xlarge"
  iam_instance_profile = aws_iam_instance_profile.enclave.name
  vpc_security_group_ids = [
    aws_security_group.enclave.id
  ]
  subnet_id = aws_subnet.enclave.id

  enclave_options {
    enabled = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "required"
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    delete_on_termination = true
    encrypted = true
  }

  user_data_replace_on_change = true
  user_data = base64encode(templatefile("./user-data.sh", { eif_s3_path = "s3://bucket/enclave.eif", tap_framer_sha256 = "e50265d7f57ce2ade393714b2c52f3173d288b348598f5a85aad1a775f49f283", memory_mb = 512, cpu_count = 2, debug_mode = "false", restart_policy = "on-failure", restart_delay_seconds = 10, ports = var.ports, http_port = var.http_port, e2e = "true", e2e_mode = "steve", locksmith = "true", egress = "false", ssh_keys = ["ssh-ed25519 AAAA test"], domain = "app.example.com" }))
  tags = {
    Name = "00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
    ConfigDomain = "app.example.com"
  }
}

resource "aws_eip" "enclave" {
  domain = "vpc"
  instance = aws_instance.enclave.id
  tags = {
    Name = "enclave-00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
  }
}

output "instance_id" {
  value = aws_instance.enclave.id
}

output "public_ip" {
  value = aws_eip.enclave.public_ip
}

output "url" {
  value = "https://app.example.com"
}

output "instance_type" {
  value = "m5.xlarge"
}

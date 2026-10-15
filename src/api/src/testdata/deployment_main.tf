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
  vpc_id = "vpc-0abc"

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
    DeploymentId = "11111111-1111-1111-1111-111111111111"
  }
}

resource "aws_instance" "enclave" {
  ami = data.aws_ami.amazon_linux_2023.id
  instance_type = "m5.xlarge"
  iam_instance_profile = "enclave-00000000-profile"
  vpc_security_group_ids = [
    aws_security_group.enclave.id
  ]
  subnet_id = "subnet-0abc"

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
  user_data = base64encode(templatefile("./user-data.sh", { eif_s3_path = "s3://bucket/e.eif", tap_framer_sha256 = "e50265d7f57ce2ade393714b2c52f3173d288b348598f5a85aad1a775f49f283", memory_mb = 512, cpu_count = 2, debug_mode = "false", restart_policy = "on-failure", restart_delay_seconds = 10, ports = var.ports, http_port = var.http_port, e2e = "false", e2e_mode = "disabled", locksmith = "false", egress = "false", ssh_keys = [], domain = "app.example.com" }))
  tags = {
    Name = "00000000-0000-0000-0000-000000000000"
    ResourceId = "00000000-0000-0000-0000-000000000000"
    ConfigDomain = "app.example.com"
    DeploymentId = "11111111-1111-1111-1111-111111111111"
  }
}

output "instance_id" {
  value = aws_instance.enclave.id
}

output "public_ip" {
  value = aws_instance.enclave.public_ip
}

output "instance_type" {
  value = aws_instance.enclave.instance_type
}

output "url" {
  value = "https://app.example.com"
}

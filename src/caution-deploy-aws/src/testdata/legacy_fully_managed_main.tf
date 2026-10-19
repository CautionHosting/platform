terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  enclave_user_data = base64gzip(templatefile("./user-data.sh", { eif_s3_path = "s3://bucket/enclave.eif", tap_framer_sha256 = "e50265d7f57ce2ade393714b2c52f3173d288b348598f5a85aad1a775f49f283", memory_mb = 512, cpu_count = 2, debug_mode = "false", restart_policy = "on-failure", restart_delay_seconds = 10, ports = [], http_port = 8080, e2e = "true", e2e_mode = "steve", locksmith = "true", egress = "false", ssh_keys = ["ssh-ed25519 AAAA test"], domain = "app.example.com", network_policy_script = templatefile("./network-policy.sh.tftpl", { egress_forward_rules = "", egress_dns_rules = "", ingress_input_rules = "-A CAUTION_INGRESS -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN\n-A CAUTION_INGRESS -s 0.0.0.0/0 -p tcp --dport 443:443 -j ACCEPT\n-A CAUTION_INGRESS -s 0.0.0.0/0 -p tcp --dport 49500:49500 -j ACCEPT\n-A CAUTION_INGRESS -s 0.0.0.0/0 -p tcp --dport 49504:49504 -j ACCEPT\n-A CAUTION_INGRESS -p tcp --dport 443:443 -j DROP\n-A CAUTION_INGRESS -p tcp --dport 49500:49500 -j DROP\n-A CAUTION_INGRESS -p tcp --dport 49500:49600 -j DROP\n-A CAUTION_INGRESS -p tcp --dport 49504:49504 -j DROP\n", ingress_ipv6_rules = "-A CAUTION_INGRESS -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN\n-A CAUTION_INGRESS -p tcp --dport 443:443 -j DROP\n-A CAUTION_INGRESS -p tcp --dport 49500:49500 -j DROP\n-A CAUTION_INGRESS -p tcp --dport 49500:49600 -j DROP\n-A CAUTION_INGRESS -p tcp --dport 49504:49504 -j DROP\n", ingress_guard_rules = "-A CAUTION_INGRESS_GUARD -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN\n-A CAUTION_INGRESS_GUARD -p tcp --dport 443:443 -j DROP\n-A CAUTION_INGRESS_GUARD -p tcp --dport 49500:49500 -j DROP\n-A CAUTION_INGRESS_GUARD -p tcp --dport 49500:49600 -j DROP\n-A CAUTION_INGRESS_GUARD -p tcp --dport 49504:49504 -j DROP\n" }), http_routes = "route {\nhandle /.well-known/caution/health {\nrespond \"OK\" 200\n}\nhandle /attestation {\nreverse_proxy localhost:49502\n}\n@caution_http_sources remote_ip 0.0.0.0/0\nhandle @caution_http_sources {\nreverse_proxy localhost:49500\n}\nhandle {\nrespond \"Forbidden\" 403\n}\n}\n" }))
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
    description = "Platform HTTP management"
  }

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
    description = "Application HTTPS ingress"
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
  user_data_base64 = local.enclave_user_data

  lifecycle {
    precondition {
      condition = length(local.enclave_user_data) <= 21844
      error_message = "Compressed enclave bootstrap exceeds the EC2 16 KiB user-data limit; reduce the network policy."
    }
  }

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

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

locals {
  resource_prefix = "stratus-red-team-ec2-serialconsole-ssh-lateral-movement"
}

variable "instance_count" {
  description = "Number of instances to create"
  default     = 3
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Ensures that serial console access is enabled in the current region
resource "aws_ec2_serial_console_access" "serial_console_access" {
  enabled = true
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 3.0"

  name = "${local.resource_prefix}-vpc"
  cidr = "10.0.0.0/16"

  azs             = [data.aws_availability_zones.available.names[0]]
  private_subnets = ["10.0.1.0/24"]
  public_subnets  = ["10.0.128.0/24"]

  map_public_ip_on_launch = false
  enable_nat_gateway      = true

  tags = {
    StratusRedTeam = true
  }
}

data "aws_ami" "amazon-2" {
  most_recent = true

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-ebs"]
  }
  owners = ["amazon"]
}

resource "aws_network_interface" "iface" {
  count     = var.instance_count
  subnet_id = module.vpc.private_subnets[0]

  private_ips = [format("10.0.1.%d", count.index + 10)]
}

resource "aws_iam_role" "instance-role" {
  name = "${local.resource_prefix}-role"
  path = "/"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "rolepolicy" {
  role       = aws_iam_role.instance-role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${local.resource_prefix}-instance"
  role = aws_iam_role.instance-role.name
}

resource "aws_instance" "instance" {
  count                = var.instance_count
  ami                  = data.aws_ami.amazon-2.id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.instance.name

  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.iface[count.index].id
  }

  tags = {
    Name = "${local.resource_prefix}-instance-${count.index}"
  }
}

output "instance_ids" {
  value = aws_instance.instance[*].id
}

output "display" {
  value = format("Instances ready: \n%s", join("\n", [
    for i in aws_instance.instance :
    format("  %s in %s", i.id, data.aws_availability_zones.available.names[0])
  ]))
}

output "instance_role_name" {
  value = aws_iam_role.instance-role.name
}
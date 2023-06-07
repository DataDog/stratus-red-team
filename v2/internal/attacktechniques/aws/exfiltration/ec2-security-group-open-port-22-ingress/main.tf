terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}
provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_get_ec2_platforms      = true
    default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

locals {
  resource_prefix = "stratus-red-team-open-sg"
}

resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "StratusRedTeamVpc",
  }
}

resource "aws_security_group" "allow_tls" {
  name        = "${local.resource_prefix}-sg"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "TLS from Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${local.resource_prefix}-sg",
  }
}

output "security_group_id" {
  value = aws_security_group.allow_tls.id
}

output "display" {
  value = format("Security group %s in VPC %s ready", aws_security_group.allow_tls.id, aws_vpc.vpc.id)
}
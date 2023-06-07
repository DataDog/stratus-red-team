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
  resource_prefix = "stratus-red-team-share-ami"
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_ebs_volume" "volume" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1

  tags = {
    Name = "${local.resource_prefix}-ami"
  }
}

resource "aws_ebs_snapshot" "snapshot" {
  volume_id = aws_ebs_volume.volume.id
}


resource "aws_ami" "ami" {
  name                = "${local.resource_prefix}-ami"
  virtualization_type = "hvm"
  root_device_name    = "/dev/xvda"

  ebs_block_device {
    device_name = "/dev/xvda"
    snapshot_id = aws_ebs_snapshot.snapshot.id
    volume_size = 1
  }
}

output "ami_id" {
  value = aws_ami.ami.id
}

output "display" {
  value = format("AMI %s is ready", aws_ami.ami.id)
}
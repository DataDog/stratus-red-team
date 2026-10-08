
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.54.0, < 5.0.0" # 4.54.0 at least is required for proper AWS SSO support, see #626
    }
  }
}
provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  default_tags {
    tags = merge(var.config.aws.tags, {
      StratusRedTeam = true
    })
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_ebs_volume" "volume" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1

  tags = {
    Name = "${var.config.aws.prefix}StratusRedTeamVolume"
  }
}

resource "aws_ram_resource_share" "ram_share" {
  name                      = "${var.config.aws.prefix}stratus-red-team-ebs-volume-share-${var.correlation.short}"
  allow_external_principals = true


  permission_arns = ["arn:aws:ram::aws:permission/AWSRAMPermissionEBSVolumeCopyAccess"]
}

output "ebs_volume_arn" {
  value = aws_ebs_volume.volume.arn
}

output "ram_resource_share_arn" {
  value = aws_ram_resource_share.ram_share.arn
}

output "display" {
  value = format("Volume %s ready", aws_ebs_volume.volume.arn)
}

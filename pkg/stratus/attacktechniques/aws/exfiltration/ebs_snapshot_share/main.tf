terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.71.0"
    }
  }
}
provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_get_ec2_platforms      = true
  skip_metadata_api_check     = true
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_ebs_volume" "volume" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1

  tags = {
    Name           = "StratusRedTeamVolume"
    StratusRedTeam = true
  }
}

resource "aws_ebs_snapshot" "snapshot" {
  volume_id = aws_ebs_volume.volume.id

  tags = {
    StratusRedTeam = true
  }
}

output "snapshot_id" {
  value = aws_ebs_snapshot.snapshot.id
}
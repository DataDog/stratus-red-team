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
  skip_metadata_api_check     = true
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

resource "aws_iam_user" "legit-user" {
  name          = "stratus-red-team-backdoor-user" # TODO parametrize
  force_destroy = true
}

output "user_name" {
  value = aws_iam_user.legit-user.name
}

output "display" {
  value = format("IAM user %s ready", aws_iam_user.legit-user.name)
}
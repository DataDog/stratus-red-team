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
    default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

resource "random_string" "random" {
  length    = 8
  min_lower = 8
}

resource "aws_iam_user" "my-user" {
  name = "stratus-red-team-${random_string.random.result}"
}

// Any output named "display" is automatically printed by Stratus Red Team after the warm-up phase
output "display" {
  value = format("IAM user %s is ready", aws_iam_user.my-user.name)
}

output "iam_user_name" {
  value = aws_iam_user.my-user.name
}
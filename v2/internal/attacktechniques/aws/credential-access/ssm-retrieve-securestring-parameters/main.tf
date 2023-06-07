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
  num_parameters = 42 // arbitrary
  prefix         = "/credentials/stratus-red-team/"
}

resource "random_password" "secret" {
  count     = local.num_parameters
  length    = 16
  min_lower = 16
}

resource "aws_ssm_parameter" "parameters" {
  count = local.num_parameters
  name  = "${local.prefix}credentials-${count.index}"
  type  = "SecureString"
  value = random_password.secret[count.index].result
}

output "display" {
  value = "${local.num_parameters} SSM parameters ready under the SSM path ${local.prefix}"
}
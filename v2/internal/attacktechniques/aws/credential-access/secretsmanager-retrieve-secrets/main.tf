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
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

locals {
  num_secrets = 20
}

resource "random_string" "secrets" {
  count     = local.num_secrets
  length    = 16
  min_lower = 16
}

resource "aws_secretsmanager_secret" "secrets" {
  count = local.num_secrets
  name  = "stratus-red-team-secret-${count.index}"

  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "secret-values" {
  count         = local.num_secrets
  secret_id     = aws_secretsmanager_secret.secrets[count.index].id
  secret_string = random_string.secrets[count.index].result
}

output "display" {
  value = format("%s Secrets Manager secrets ready", local.num_secrets)
}
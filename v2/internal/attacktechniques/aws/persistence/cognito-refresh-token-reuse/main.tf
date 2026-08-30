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
  skip_get_ec2_platforms      = true
  default_tags {
    tags = merge(var.config.aws.tags, {
      StratusRedTeam = true
    })
  }
}

locals {
  resource_prefix = "${var.config.aws.prefix}stratus-red-team-cognito-refresh-${var.correlation.short}"
  # Permanent password for the test user. It is only used during warm-up to obtain an
  # initial refresh token that the detonation phase later reuses. It is never a real secret.
  user_password = "Str@tus-Red-Team-${var.correlation.short}-1"
}

resource "aws_cognito_user_pool" "victim" {
  name = "${local.resource_prefix}-pool"

  # Relax the password policy so the deterministic warm-up password above is always accepted.
  password_policy {
    minimum_length    = 8
    require_lowercase = false
    require_numbers   = false
    require_symbols   = false
    require_uppercase = false
  }
}

resource "aws_cognito_user_pool_client" "victim" {
  name         = "${local.resource_prefix}-client"
  user_pool_id = aws_cognito_user_pool.victim.id

  # No client secret keeps the token-exchange call as simple as it is for an attacker
  # who only possesses a refresh token and the (public) app client ID.
  generate_secret         = false
  enable_token_revocation = true

  explicit_auth_flows = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH", # used during warm-up to obtain the initial refresh token
    "ALLOW_REFRESH_TOKEN_AUTH",       # allows exchanging a refresh token for new tokens
  ]

  # A long refresh-token validity is what makes a stolen refresh token useful for persistence.
  refresh_token_validity = 30 # days
  access_token_validity  = 60 # minutes
  id_token_validity      = 60 # minutes
  token_validity_units {
    refresh_token = "days"
    access_token  = "minutes"
    id_token      = "minutes"
  }
}

resource "aws_cognito_user" "victim" {
  user_pool_id   = aws_cognito_user_pool.victim.id
  username       = "victim-${var.correlation.short}"
  password       = local.user_password
  message_action = "SUPPRESS"
}

output "user_pool_id" {
  value = aws_cognito_user_pool.victim.id
}

output "client_id" {
  value = aws_cognito_user_pool_client.victim.id
}

output "username" {
  value = aws_cognito_user.victim.username
}

output "password" {
  value     = local.user_password
  sensitive = true
}

output "display" {
  value = format(
    "Cognito user pool %s with app client %s and test user %s ready",
    aws_cognito_user_pool.victim.id,
    aws_cognito_user_pool_client.victim.id,
    aws_cognito_user.victim.username,
  )
}

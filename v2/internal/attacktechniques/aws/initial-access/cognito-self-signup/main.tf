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

data "aws_region" "current" {}

locals {
  resource_prefix = "${var.config.aws.prefix}stratus-red-team-cognito-${var.correlation.short}"
}

# Pre-sign-up Lambda trigger that auto-confirms (and auto-verifies) any user that
# self-registers. This emulates a misconfigured user pool where anyone can sign up and
# immediately authenticate, with no email/SMS confirmation step in the loop.
resource "aws_iam_role" "lambda" {
  name = "${local.resource_prefix}-lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_s3_bucket" "lambda_code" {
  bucket        = "${local.resource_prefix}-code"
  force_destroy = true
}

# Inline zip of a Node.js pre-sign-up handler that sets autoConfirmUser/autoVerifyEmail.
resource "aws_s3_object" "lambda_code" {
  bucket         = aws_s3_bucket.lambda_code.id
  key            = "index.zip"
  content_base64 = "UEsDBBQAAAAIAAAIIVDO82CiiAAAANwAAAAIAAAAaW5kZXguanN9jU0KwjAQRvc9xayK3eQCoYKIR9B91AkG2kmdH7FI726MLlyIi1l8zHs8vE+ZVdwl0HlAhh6CzHSCFd6QtIN+DY8GoC7HKFMmQRdM8zZTTDzupVrKhr6AKX7UAl8NRZ0VYKPK6WiKAm0L//4Ox5CGrkZ/Zg/IKc67F/WVXcoxqjG9Hd8svnkCUEsBAh4DFAAAAAgAAAghUM7zYKKIAAAA3AAAAAgAAAAAAAAAAQAAAKSBAAAAAGluZGV4LmpzUEsFBgAAAAABAAEANgAAAK4AAAAAAA=="
}

resource "aws_lambda_function" "autoconfirm" {
  function_name = "${local.resource_prefix}-autoconfirm"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  s3_bucket     = aws_s3_bucket.lambda_code.id
  s3_key        = aws_s3_object.lambda_code.key
}

resource "aws_cognito_user_pool" "pool" {
  name = "${local.resource_prefix}-pool"

  lambda_config {
    pre_sign_up = aws_lambda_function.autoconfirm.arn
  }
}

resource "aws_lambda_permission" "cognito" {
  statement_id  = "AllowCognitoInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.autoconfirm.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn    = aws_cognito_user_pool.pool.arn
}

# Public app client with no secret, allowing the SRP authentication flow. This is what an
# unauthenticated attacker would use to self-register and authenticate.
resource "aws_cognito_user_pool_client" "client" {
  name                = "${local.resource_prefix}-client"
  user_pool_id        = aws_cognito_user_pool.pool.id
  generate_secret     = false
  explicit_auth_flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
}

# Identity pool that federates authenticated user pool users into AWS credentials.
resource "aws_cognito_identity_pool" "identity_pool" {
  identity_pool_name               = "${local.resource_prefix}-idpool"
  allow_unauthenticated_identities = false

  cognito_identity_providers {
    client_id               = aws_cognito_user_pool_client.client.id
    provider_name           = "cognito-idp.${data.aws_region.current.name}.amazonaws.com/${aws_cognito_user_pool.pool.id}"
    server_side_token_check = false
  }
}

# Role handed out to authenticated identities. It intentionally carries no permissions:
# the technique emulates obtaining the credentials, not abusing an over-privileged role.
resource "aws_iam_role" "authenticated" {
  name = "${local.resource_prefix}-auth-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "cognito-identity.amazonaws.com" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.identity_pool.id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
EOF
}

resource "aws_cognito_identity_pool_roles_attachment" "roles" {
  identity_pool_id = aws_cognito_identity_pool.identity_pool.id

  roles = {
    authenticated = aws_iam_role.authenticated.arn
  }
}

# The authenticated role's trust policy takes several seconds to propagate before Cognito can
# assume it via GetCredentialsForIdentity. Wait so a detonation right after warm-up succeeds.
resource "time_sleep" "wait_for_iam_propagation" {
  depends_on      = [aws_cognito_identity_pool_roles_attachment.roles, aws_iam_role.authenticated]
  create_duration = "30s"
}

output "user_pool_id" {
  value = aws_cognito_user_pool.pool.id
}

output "client_id" {
  value = aws_cognito_user_pool_client.client.id
}

output "identity_pool_id" {
  value = aws_cognito_identity_pool.identity_pool.id
}

output "warmup_short_id" {
  value = var.correlation.short
}

output "display" {
  value = format("Cognito user pool %s with public self-signup and identity pool %s ready",
    aws_cognito_user_pool.pool.id,
    aws_cognito_identity_pool.identity_pool.id
  )
}

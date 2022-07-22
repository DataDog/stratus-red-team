terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16.0"
    }
  }
}
provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_get_ec2_platforms      = true
  skip_metadata_api_check     = true
}

data "aws_caller_identity" "current" {}

resource "random_string" "suffix" {
  length    = 8
  min_lower = 8
  special   = false
}

resource "aws_iam_user" "console-user" {
  name          = "console-user-${random_string.suffix.result}"
  force_destroy = true
}

// Allows the IAM user to authenticate through the AWS Console
resource "aws_iam_user_login_profile" "login-profile" {
  user                    = aws_iam_user.console-user.name
  password_length         = 16
  password_reset_required = false
}

// The IAM user profile takes a few seconds to be effective on AWS.
// We need to delay the warm-up by a few seconds
resource "null_resource" "previous" {}
resource "time_sleep" "wait" {
  depends_on      = [null_resource.previous]
  create_duration = "10s"
}

output "display" {
  value = format("IAM user %s ready (password: %s). Sign-in link: %s",
    aws_iam_user.console-user.name,
    aws_iam_user_login_profile.login-profile.password,
    "https://${data.aws_caller_identity.current.account_id}.signin.aws.amazon.com/console"
  )
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "username" {
  value = aws_iam_user.console-user.name
}

output "password" {
  value = aws_iam_user_login_profile.login-profile.password
}
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
  resource_prefix = "stratus-red-team-user-federation"
}

resource "aws_iam_user" "legit-user" {
  name          = "${local.resource_prefix}-user"
  force_destroy = true
}

data "aws_iam_policy_document" "legit-user-policy-document" {
  statement {
    effect    = "Allow"
    actions   = [
      "sts:GetFederationToken",
      "iam:UpdateAccessKey",
      "iam:ListAccessKeys"
      ]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "legit-user-policy" {
  name   = "test"
  user   = aws_iam_user.legit-user.name
  policy = data.aws_iam_policy_document.legit-user-policy-document.json
}

resource "aws_iam_access_key" "inactive-credentials" {
  user    = aws_iam_user.legit-user.name
  status  = "Inactive"
}

resource "aws_iam_access_key" "active-credentials" {
  user    = aws_iam_user.legit-user.name
  status  = "Active"
}

output "user_name" {
  value = aws_iam_user.legit-user.name
}

output "access_key_id" {
  value = aws_iam_access_key.active-credentials.id
}

output "secret_access_key" {
  value = aws_iam_access_key.active-credentials.secret
  sensitive = true
}

output "display" {
  value = format("IAM user %s ready", aws_iam_user.legit-user.name)
}

output "access_key_create_date" {
    value = aws_iam_access_key.active-credentials.create_date
}
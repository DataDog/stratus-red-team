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
  resource_prefix = "stratus-red-team-leave-org"
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "role" {
  name = "${local.resource_prefix}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = data.aws_caller_identity.current.account_id
        }
      },
    ]
  })

  // Limited policy, which will cause access denied on organizations:LeaveOrganization
  inline_policy {
    name = "inline-policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = ["ec2:Describe*"]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }
}

output "role_arn" {
  value = aws_iam_role.role.arn
}
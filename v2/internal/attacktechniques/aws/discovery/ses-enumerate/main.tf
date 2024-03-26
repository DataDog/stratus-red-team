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
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

locals {
  resource_prefix = "stratus-red-team-ses-enumerate"
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "ses_enumerate_role" {
  name = "${local.resource_prefix}-role"
  path = "/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = data.aws_caller_identity.current.account_id
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rolepolicy" {
  role       = aws_iam_role.ses_enumerate_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESReadOnlyAccess"
}

output "role_arn" {
  value = aws_iam_role.ses_enumerate_role.arn
}

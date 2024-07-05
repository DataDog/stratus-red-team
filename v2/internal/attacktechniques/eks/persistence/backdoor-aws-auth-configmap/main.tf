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
}

locals {
  resource_prefix = "stratus-red-team-eks-backdoor-aws-auth"
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "role" {
  name = "${local.resource_prefix}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.account_id
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "role-policy" {
  role       = aws_iam_role.role.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

output "role_arn" {
  value = aws_iam_role.role.arn
}

output "display" {
  value = format("IAM role %s ready", aws_iam_role.role.arn)
}
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
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

data "aws_caller_identity" "current" {}

resource "random_string" "suffix" {
  length    = 8
  min_lower = 8
  special   = false
}

resource "aws_iam_role" "role" {
  name = "sample-role-used-by-stratus-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAssumeRole"
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.account_id
        }
      },
    ]
  })
}

resource "aws_iam_policy" "policy" {
  name = "inline-policy-${random_string.suffix.result}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["ec2:DescribeInstances"]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy_attachment" "attachment" {
  name       = "iam-policy-attachement-${random_string.suffix.result}"
  roles      = [aws_iam_role.role.name]
  policy_arn = aws_iam_policy.policy.arn
}

output "role_arn" {
  value       = aws_iam_role.role.arn
  description = "Arn of the created role"
}

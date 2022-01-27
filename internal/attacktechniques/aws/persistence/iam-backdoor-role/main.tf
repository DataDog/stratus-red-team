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
}

resource "aws_iam_role" "legit-role" {
  name = "sample-legit-role" # TODO parametrize
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "role-policy" {
  role       = aws_iam_role.legit-role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "role_name" {
  value = aws_iam_role.legit-role.name
}

output "role_trust_policy" {
  value = aws_iam_role.legit-role.assume_role_policy
}

output "display" {
  value = format("IAM role %s ready", aws_iam_role.legit-role.name)
}
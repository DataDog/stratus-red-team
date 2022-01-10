terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.71.0"
    }
  }
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

  tags = {
    StratusRedTeam = true
  }
}

resource "aws_iam_role_policy_attachment" "role-policy" {
  role       = aws_iam_role.legit-role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
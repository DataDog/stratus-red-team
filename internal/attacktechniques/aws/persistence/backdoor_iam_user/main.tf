terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.71.0"
    }
  }
}

resource "aws_iam_user" "legit-user" {
  name = "sample-legit-user" # TODO parametrize
  force_destroy = true
}
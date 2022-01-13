terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.71.0"
    }
  }
}
provider "aws" {
  skip_region_validation = true
  skip_credentials_validation = true
  skip_get_ec2_platforms = true
  skip_metadata_api_check = true
}

resource "aws_iam_user" "legit-user" {
  name = "sample-legit-user" # TODO parametrize
  force_destroy = true
}
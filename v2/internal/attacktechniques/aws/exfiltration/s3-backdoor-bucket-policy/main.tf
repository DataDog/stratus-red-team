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
  skip_metadata_api_check     = true
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

resource "random_string" "suffix" {
  length    = 10
  min_lower = 10
  special   = false
}

locals {
  resource_prefix = "stratus-red-team-bdbp" # backdoor bucket policy
}

resource "aws_s3_bucket" "bucket" {
  bucket = "${local.resource_prefix}-${random_string.suffix.result}"
}

output "bucket_name" {
  value = aws_s3_bucket.bucket.id
}

output "display" {
  value = format("S3 bucket %s ready", aws_s3_bucket.bucket.id)
}
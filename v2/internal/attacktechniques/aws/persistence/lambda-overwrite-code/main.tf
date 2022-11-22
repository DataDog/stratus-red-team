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

resource "random_string" "suffix" {
  length    = 10
  min_lower = 10
  special   = false
}

locals {
  resource_prefix = "stratus-red-team-olc" # stratus red team overwrite lambda code 
}

resource "aws_iam_role" "lambda-update" {
  name = "${local.resource_prefix}-lambda-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "lambda.amazonaws.com",
        },
        "Action" : "sts:AssumeRole",
        "Condition" : {}
      }
    ]
  })

}


resource "aws_s3_bucket" "bucket" {
  bucket        = "${local.resource_prefix}-bucket-${random_string.suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_acl" "bucket_acl" {
  bucket = aws_s3_bucket.bucket.id
  acl    = "private"
}

resource "aws_s3_object" "lambda_zip" {
  bucket         = aws_s3_bucket.bucket.id
  key            = "lambda.zip"
  content_base64 = "UEsDBAoDAAAAAFMA01QaUYiFIwAAACMAAAAJAAAAbGFtYmRhLnB5ZGVmIGxhbWJkYV9oYW5kbGVyKGUsIGMpOgogICAgcGFzcwpQSwECPwMKAwAAAABTANNUGlGIhSMAAAAjAAAACQAkAAAAAAAAACCApIEAAAAAbGFtYmRhLnB5CgAgAAAAAAABABgAgHzXHl+D2AEAE3AfX4PYAYB81x5fg9gBUEsFBgAAAAABAAEAWwAAAEoAAAAAAA=="
}

resource "aws_lambda_function" "lambda" {
  function_name = "${local.resource_prefix}-func-${random_string.suffix.result}"
  s3_bucket     = aws_s3_bucket.bucket.id
  s3_key        = aws_s3_object.lambda_zip.key
  role          = aws_iam_role.lambda-update.arn
  handler       = "lambda.lambda_handler"
  runtime       = "python3.9"
}

output "lambda_function_name" {
  value = aws_lambda_function.lambda.function_name
}

output "bucket_name" {
  value = aws_s3_bucket.bucket.id
}

output "bucket_object_key" {
  value = aws_s3_object.lambda_zip.id
}

output "display" {
  value = format("Lambda function %s is ready", aws_lambda_function.lambda.arn)
}
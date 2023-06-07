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
  resource_prefix = "stratus-red-team-backdoor-f"
}

resource "aws_iam_role" "lambda" {
  name = "${local.resource_prefix}-lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "random_string" "suffix" {
  length    = 10
  min_lower = 10
  special   = false
}

resource "aws_s3_bucket" "bucket" {
  bucket        = "${local.resource_prefix}-bucket-${random_string.suffix.result}"
  force_destroy = true
}
resource "aws_s3_bucket_object" "code" {
  bucket         = aws_s3_bucket.bucket.id
  key            = "index.zip"
  content_base64 = "UEsDBBQAAAAIAJuwM1S3dfsVfQAAAJEAAAAHABwAbWFpbi5qc1VUCQAD9nzoYfd86GF1eAsAAQT2AQAABBQAAAA1zLEOgjAQgOG9T3FhopF0YDRxZHGoA8bJpakHNilXcr0aCPHdlYHxH74flzmxZPN29IrIcAFweSUPQyEvIVGNHyRpwCcSXETDpmCPnCKamMa66h6dvZ/hSRWc4NrfrMnCgcYwrAemEmMDrdZ/yyiF6fjti14Y3WTdhOqrflBLAQIeAxQAAAAIAJuwM1S3dfsVfQAAAJEAAAAHABgAAAAAAAEAAACkgQAAAABtYWluLmpzVVQFAAP2fOhhdXgLAAEE9gEAAAQUAAAAUEsFBgAAAAABAAEATQAAAL4AAAAAAA=="
}

resource "aws_lambda_function" "lambda" {
  function_name = "${local.resource_prefix}-func"
  s3_bucket     = aws_s3_bucket.bucket.id
  s3_key        = aws_s3_bucket_object.code.key
  role          = aws_iam_role.lambda.arn
  handler       = "index.test"
  runtime       = "nodejs18.x"
}

output "lambda_function_name" {
  value = aws_lambda_function.lambda.function_name
}

output "display" {
  value = format("Lambda function %s is ready", aws_lambda_function.lambda.arn)
}
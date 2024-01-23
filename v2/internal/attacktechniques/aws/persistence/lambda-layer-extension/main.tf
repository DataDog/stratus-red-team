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
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

locals {
  resource_prefix = "stratus-red-team-lambda-layer"
}

resource "aws_iam_role" "lambda_role" {
  name = "${local.resource_prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          "Service" : [
            "lambda.amazonaws.com"
          ]
        }
      },
    ]
  })
}

resource "aws_iam_policy" "lambda_logs" {
  name        = "${local.resource_prefix}-lambda-logs"
  description = "Allows Lambda function to write logs to CloudWatch"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_logs_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_logs.arn
}


resource "random_string" "suffix" {
  length    = 6
  min_lower = 6
  special   = false
}

resource "aws_s3_bucket" "bucket" {
  bucket        = "${local.resource_prefix}-${random_string.suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_object" "code" {
  bucket         = aws_s3_bucket.bucket.id
  key            = "simpleLambda.zip"
  content_base64 = "UEsDBBQACAAIAAAAIYoAAAAAAAAAAAAAAAAPAAAAc2ltcGxlTGFtYmRhLnB5RIuxCgIxEAX7+4pntQpXHJZpbSws/IWcu8cJya4ke2IQ/11M43TDMCwL1qicpOzlKeojbqYuLz+EAQCK+FYU7y4/qHr0rZ6MhQKO0zT+02zcKIDOkpJhKZaRG+o9P5Lg2nw1xSXmmeOO+vUZvgEAAP//UEsHCCE/h3lyAAAAgQAAAFBLAQIUAxQACAAIAAAAIYohP4d5cgAAAIEAAAAPAAAAAAAAAAAAAACkgQAAAABzaW1wbGVMYW1iZGEucHlQSwUGAAAAAAEAAQA9AAAArwAAAAAA"
}

resource "aws_lambda_function" "lambda" {
  s3_bucket     = aws_s3_bucket.bucket.id
  s3_key        = aws_s3_bucket_object.code.key
  function_name = "${local.resource_prefix}-simpleLambda"
  role          = aws_iam_role.lambda_role.arn
  handler       = "${local.resource_prefix}-simpleLambda.handler"
  timeout       = 20

  runtime = "python3.10"

  publish = true
}

resource "aws_s3_bucket_object" "code_layer" {
  bucket         = aws_s3_bucket.bucket.id
  key            = "simpleLayer.zip"
  content_base64 = "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"
}

resource "aws_lambda_layer_version" "lambda_extension_layer" {
  s3_bucket  = aws_s3_bucket.bucket.id
  s3_key     = aws_s3_bucket_object.code_layer.key
  layer_name = "${local.resource_prefix}-my-lambda-extension"

  compatible_runtimes = ["python3.10"]
}

output "lambda_extension_layer_arn" {
  value = aws_lambda_layer_version.lambda_extension_layer.arn
}

output "lambda_arn" {
  value = aws_lambda_function.lambda.arn
}
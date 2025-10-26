terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.15.0"
    }
  }
}
provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
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
  resource_prefix = "stratus-red-team-bedrock-access-s3" # backdoor bucket policy
  code_interpreter_name = "${replace(local.resource_prefix, "-", "_")}"
}

resource "aws_s3_bucket" "bucket" {
  bucket = "${local.resource_prefix}-${random_string.suffix.result}"
}

resource "aws_s3_object" "file" {
  bucket  = aws_s3_bucket.bucket.id
  key     = "customer.csv"
  content = <<EOF
id,name,email,phone
1,John Doe,john.doe@example.com,000-000-0000
EOF
  acl     = "private"
}

resource "aws_iam_role" "bedrock_agent_role" {
  name = "${local.resource_prefix}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "bedrock-agentcore.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "bedrock_agent_s3_policy" {
  name = "${local.resource_prefix}-policy"
  role = aws_iam_role.bedrock_agent_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowS3GetPutForArtifacts"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.bucket.arn}/*"
      }
    ]
  })
}

resource "aws_bedrockagentcore_code_interpreter" "default" {
  name               = "${local.code_interpreter_name}"
  description        = "Code interpreter with custom execution role"
  execution_role_arn = aws_iam_role.bedrock_agent_role.arn

  network_configuration {
    network_mode = "PUBLIC"
  }
}

output "bucket_name" {
  value = aws_s3_bucket.bucket.id
}

output "code_interpreter" {
  value = aws_bedrockagentcore_code_interpreter.default.code_interpreter_id
}

output "display" {
  value = format("S3 bucket %s ready", aws_s3_bucket.bucket.id)
}
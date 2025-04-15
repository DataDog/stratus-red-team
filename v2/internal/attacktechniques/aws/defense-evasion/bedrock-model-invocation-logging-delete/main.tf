terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.31.0"
    }
  }
}

provider "aws" {
  region                      = "ca-central-1"
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
  resource_prefix = "stratus-red-team-bedrock"
}

# Create the CloudWatch log group
resource "aws_cloudwatch_log_group" "bedrock_logs" {
  name = "${local.resource_prefix}-logs-${random_string.suffix.result}"
}

# Create IAM role for Bedrock to write logs
resource "aws_iam_role" "bedrock_logging" {
  name = "${local.resource_prefix}-role-${random_string.suffix.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "bedrock.amazonaws.com"
        }
      }
    ]
  })
}

# Allow Bedrock to write CloudWatch logs
resource "aws_iam_role_policy" "bedrock_logging" {
  name = "${local.resource_prefix}-policy-${random_string.suffix.result}"
  role = aws_iam_role.bedrock_logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.bedrock_logs.arn}:*"
      }
    ]
  })
}

resource "aws_bedrock_model_invocation_logging_configuration" "test_logging" {
  logging_config {
    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.bedrock_logs.name
      role_arn       = aws_iam_role.bedrock_logging.arn
    }
    text_data_delivery_enabled      = true
    embedding_data_delivery_enabled = true
    image_data_delivery_enabled     = true
  }

  depends_on = [aws_cloudwatch_log_group.bedrock_logs, aws_iam_role_policy.bedrock_logging]
}

output "bedrock_logging_config_id" {
  value = aws_bedrock_model_invocation_logging_configuration.test_logging.id
}

output "display" {
  value = format("Bedrock model invocation logging configuration %s ready", aws_bedrock_model_invocation_logging_configuration.test_logging.id)
}

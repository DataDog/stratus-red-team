terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.31.0"
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
  resource_prefix = "stratus-red-team-bedrock"
}

resource "aws_bedrock_guardrail" "test_guardrail" {
  name                      = "${local.resource_prefix}-guardrail-${random_string.suffix.result}"
  description               = "Test guardrail for Stratus Red Team"
  blocked_input_messaging   = "This input is not allowed"
  blocked_outputs_messaging = "This output is not allowed"

  content_policy_config {
    filters_config {
      input_strength  = "MEDIUM"
      output_strength = "MEDIUM"
      type            = "HATE"
    }
  }
}

output "bedrock_guardrail_id" {
  value = aws_bedrock_guardrail.test_guardrail.guardrail_id
}

output "display" {
  value = format("Bedrock guardrail %s ready", aws_bedrock_guardrail.test_guardrail.name)
}

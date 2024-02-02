terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0.0"
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
  resource_prefix = "stratus-red-team-dns-delete"
}

locals {
  bucket-name = "${local.resource_prefix}-bucket-${random_string.suffix.result}"
}

resource "aws_route53_resolver_query_log_config" "config" {
  name            = "${local.resource_prefix}-config-${random_string.suffix.result}"
  destination_arn = aws_s3_bucket.query_log.arn
}

resource "aws_s3_bucket" "query_log" {
  bucket        = local.bucket-name
  force_destroy = true
}

output "route53_logger_id" {
  value = aws_route53_resolver_query_log_config.config.id
}

output "display" {
  value = format("Route53 query log config %s is ready", aws_route53_resolver_query_log_config.config.name)
}

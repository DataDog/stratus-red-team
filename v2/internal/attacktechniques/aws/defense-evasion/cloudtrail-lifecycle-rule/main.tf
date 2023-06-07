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

resource "random_string" "suffix" {
  length    = 10
  min_lower = 10
  special   = false
}

locals {
  resource_prefix = "stratus-red-team-ctlr" # cloudtrail lifecycle rule
}

locals {
  bucket-name = "${local.resource_prefix}-bucket-${random_string.suffix.result}"
}

resource "aws_cloudtrail" "trail" {
  name           = "${local.resource_prefix}-trail-${random_string.suffix.result}"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = local.bucket-name
  force_destroy = true

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${local.bucket-name}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${local.bucket-name}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

output "cloudtrail_trail_name" {
  value = aws_cloudtrail.trail.name
}

output "s3_bucket_name" {
  value = aws_s3_bucket.cloudtrail.id
}

output "display" {
  value = format("CloudTrail trail %s ready, logging to S3 bucket %s", aws_cloudtrail.trail.arn, aws_s3_bucket.cloudtrail.id)
}
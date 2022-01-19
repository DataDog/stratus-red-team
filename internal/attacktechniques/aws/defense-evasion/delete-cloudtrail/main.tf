terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.71.0"
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

resource "aws_cloudtrail" "trail" {
  name = "my-cloudtrail-trail-2"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id
}

resource "random_string" "suffix" {
  length    = 16
  min_lower = 16
  special   = false
}

locals {
  bucket-name = "my-cloudtrail-bucket-${random_string.suffix.result}"
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

output "display" {
  value = format("CloudTrail trail %s ready", aws_cloudtrail.trail.arn)
}
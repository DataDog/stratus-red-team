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
  resource_prefix = "stratus-red-team-remove-flow-logs"
}

resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_flow_log" "flow-logs" {
  iam_role_arn    = aws_iam_role.role.arn
  log_destination = aws_cloudwatch_log_group.logs.arn
  traffic_type    = "REJECT"
  vpc_id          = aws_vpc.vpc.id
}

resource "aws_cloudwatch_log_group" "logs" {
  name = "/stratus-red-team/vpc-flow-logs"
}

resource "aws_iam_role" "role" {
  name = "${local.resource_prefix}-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "example" {
  name = "${local.resource_prefix}-policy"
  role = aws_iam_role.role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

output "vpc_id" {
  value = aws_vpc.vpc.id
}

output "flow_logs_id" {
  value = aws_flow_log.flow-logs.id
}

output "display" {
  value = format("VPC Flow Logs %s in VPC %s ready", aws_flow_log.flow-logs.id, aws_vpc.vpc.id)
}
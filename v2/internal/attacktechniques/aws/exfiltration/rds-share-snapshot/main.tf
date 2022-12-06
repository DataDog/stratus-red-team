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
  skip_metadata_api_check     = true
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}

resource "random_password" "password" {
  length    = 32
  min_lower = 32
  special   = false
}

locals {
  resource_prefix = "stratus-red-team-share-snap"
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "${local.resource_prefix}-vpc"
  cidr = "10.0.0.0/16"

  azs              = [data.aws_availability_zones.available.names[0], data.aws_availability_zones.available.names[1]]
  database_subnets = ["10.0.1.0/24", "10.0.2.0/24"]

  map_public_ip_on_launch = false
  enable_nat_gateway      = false

  tags = {
    StratusRedTeam = true
  }
}

resource "aws_db_instance" "default" {
  allocated_storage       = 10 // minimum size
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  name                    = "${replace(local.resource_prefix, "-", "")}db"
  backup_retention_period = 0
  db_subnet_group_name    = module.vpc.database_subnet_group_name
  username                = "admin"
  password                = random_password.password.result
  skip_final_snapshot     = true
  apply_immediately       = true
}

resource "aws_db_snapshot" "snapshot" {
  db_instance_identifier = aws_db_instance.default.id
  db_snapshot_identifier = "exfiltration"
}

output "rds_instance_id" {
  value = aws_db_instance.default.id
}

output "snapshot_id" {
  value = aws_db_snapshot.snapshot.id
}

output "display" {
  value = format("RDS Snapshot %s of RDS Instance %s is ready", aws_db_snapshot.snapshot.id, aws_db_instance.default.id)
}
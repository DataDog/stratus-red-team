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

resource "random_password" "password" {
  length    = 32
  min_lower = 32
  special   = false
}

resource "aws_db_instance" "default" {
  allocated_storage    = 10 // minimum size
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  name                 = "samplerdsdatabase"
  backup_retention_period = 0
  username = "admin"
  password = random_password.password.result
  skip_final_snapshot  = true
  apply_immediately = true
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
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.3.2"
    }
  }
}

locals {
  resource_prefix = "stratus-red-team-scsb" # share cloud sql backup
}

resource "random_string" "suffix" {
  length    = 8
  special   = false
  min_lower = 8
}

resource "google_sql_database_instance" "instance" {
  name             = "${local.resource_prefix}-${random_string.suffix.result}"
  database_version = "MYSQL_8_0"
  region           = "us-central1"
  deletion_protection = false

  settings {
    tier = "db-f1-micro"

    backup_configuration {
      enabled = true
    }
  }
}

resource "google_storage_bucket" "export_bucket" {
  name                        = "${local.resource_prefix}-export-${random_string.suffix.result}"
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = true

  public_access_prevention = "inherited"
}

# Grant the Cloud SQL service account write access to the export bucket.
# This is required for Cloud SQL to write the export file.
data "google_sql_database_instance" "instance_data" {
  name = google_sql_database_instance.instance.name
}

resource "google_storage_bucket_iam_member" "sql_export_writer" {
  bucket = google_storage_bucket.export_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${data.google_sql_database_instance.instance_data.service_account_email_address}"
}

output "instance_name" {
  value = google_sql_database_instance.instance.name
}

output "bucket_name" {
  value = google_storage_bucket.export_bucket.name
}

output "display" {
  value = format("Cloud SQL instance %s ready with export bucket %s", google_sql_database_instance.instance.name, google_storage_bucket.export_bucket.name)
}

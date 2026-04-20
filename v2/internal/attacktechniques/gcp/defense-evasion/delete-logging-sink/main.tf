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
  resource_prefix = "stratus-red-team-dls" # stratus red team delete logging sink
}

resource "random_string" "suffix" {
  length    = 8
  special   = false
  min_lower = 8
}

resource "google_storage_bucket" "log_bucket" {
  name          = "${local.resource_prefix}-bucket-${random_string.suffix.result}"
  location      = "US"
  force_destroy = true
}

resource "google_logging_project_sink" "audit_sink" {
  name        = "${local.resource_prefix}-sink-${random_string.suffix.result}"
  destination = "storage.googleapis.com/${google_storage_bucket.log_bucket.name}"
  filter      = "logName:\"cloudaudit.googleapis.com\""

  unique_writer_identity = true
}

resource "google_storage_bucket_iam_member" "sink_writer" {
  bucket = google_storage_bucket.log_bucket.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit_sink.writer_identity
}

output "sink_name" {
  value = google_logging_project_sink.audit_sink.name
}

output "display" {
  value = format("Log sink %s forwarding audit logs to gs://%s", google_logging_project_sink.audit_sink.name, google_storage_bucket.log_bucket.name)
}

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
  resource_prefix = "stratus-red-team-rgbd" # ransomware gcs batch deletion
}

resource "random_string" "suffix" {
  length    = 8
  special   = false
  min_lower = 8
}

resource "google_storage_bucket" "bucket" {
  name          = "${local.resource_prefix}-${random_string.suffix.result}"
  location      = "US"
  force_destroy = true
}

resource "google_storage_bucket_object" "objects" {
  count   = 50
  name    = "sensitive-data-${count.index}.txt"
  bucket  = google_storage_bucket.bucket.name
  content = "Sensitive data file ${count.index} - Stratus Red Team test"
}

output "bucket_name" {
  value = google_storage_bucket.bucket.name
}

output "display" {
  value = format("GCS bucket %s with 50 objects", google_storage_bucket.bucket.name)
}

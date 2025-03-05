terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
  }
}

provider "google" {
  default_labels = {
    stratus-red-team = "true"
  }
}

locals {
  resource_prefix = "stratus-red-team-bbp"
  location        = "ASIA"
}

resource "random_string" "suffix" {
  special = false
  length  = 16
  min_lower = 16
}

resource "google_storage_bucket" "bucket" {
  name = "${local.resource_prefix}-bucket-${random_string.suffix.result}"

  location      = local.location
  storage_class = "STANDARD"
  force_destroy = true
  uniform_bucket_level_access = true
}

output "bucket_name" {
  value = google_storage_bucket.bucket.name
}

output "display" {
  value = format("Storage Bucket '%s' ready", google_storage_bucket.bucket.name)  
}
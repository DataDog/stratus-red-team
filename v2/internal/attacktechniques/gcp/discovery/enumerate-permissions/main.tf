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
  resource_prefix = "stratus-red-team-ep" # stratus red team enumerate permissions
}

resource "google_service_account" "sa" {
  account_id   = "${local.resource_prefix}-sa"
  display_name = "Stratus Red Team - Permission Enumeration"
  description  = "Service account used by Stratus Red Team for gcp.discovery.enumerate-permissions"
}

resource "google_service_account_key" "key" {
  service_account_id = google_service_account.sa.name
}

output "sa_key" {
  value     = google_service_account_key.key.private_key
  sensitive = true
}

output "project_id" {
  value = google_service_account.sa.project
}

output "sa_email" {
  value = google_service_account.sa.email
}

output "display" {
  value = format("Service account %s ready for permission enumeration", google_service_account.sa.email)
}

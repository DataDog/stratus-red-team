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

resource "google_project_iam_member" "sa_storage_object_viewer" {
  project = google_service_account.sa.project
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.sa.email}"
}

data "google_project" "target" {
  project_id = google_service_account.sa.project
}

data "google_iam_testable_permissions" "project" {
  full_resource_name = "//cloudresourcemanager.googleapis.com/projects/${data.google_project.target.number}"
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

output "testable_permissions" {
  value = join(",", [
    for permission in data.google_iam_testable_permissions.project.permissions : permission.name
  ])
}

output "display" {
  value = format("Service account %s ready for permission enumeration", google_service_account.sa.email)
}

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.28.0"
    }
  }
}

data "google_project" "current" {}

locals {
  resource_prefix = "stratus-red-team-bip" # stratus red team backdoor iam policy
}

resource "google_service_account" "service_account" {
  account_id = format("%s-sa", local.resource_prefix)
}

resource "google_project_iam_member" "binding" {
  project = data.google_project.current.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.service_account.email}"
}

output "sa_email" {
  value = google_service_account.service_account.email
}

output "sa_id" {
  value = google_service_account.service_account.id
}

output "display" {
  value = format("Service account %s ready", google_service_account.service_account.email)
}
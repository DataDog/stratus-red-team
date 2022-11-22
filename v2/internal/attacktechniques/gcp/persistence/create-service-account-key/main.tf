terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.28.0"
    }
  }
}

locals {
  resource_prefix = "stratus-red-team-csak" # stratus red team create service account key
}

resource "google_service_account" "service_account" {
  account_id = format("%s-sa", local.resource_prefix)
}

output "sa_email" {
  value = google_service_account.service_account.email
}

output "display" {
  value = format("Service account %s ready", google_service_account.service_account.email)
}
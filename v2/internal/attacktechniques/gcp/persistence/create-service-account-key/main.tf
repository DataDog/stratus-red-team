terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.28.0"
    }
  }
}

resource "google_service_account" "service_account" {
  account_id = "target-sa-stratus-red-team"
}

output "sa_email" {
  value = google_service_account.service_account.email
}

output "display" {
  value = format("Service account %s ready", google_service_account.service_account.email)
}
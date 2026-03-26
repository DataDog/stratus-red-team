terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
  }
}

# Enable Data Access audit logs for Cloud Storage so we have something
# to remove during detonation.
resource "google_project_iam_audit_config" "storage_audit" {
  project = data.google_project.current.project_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

data "google_project" "current" {}

output "service" {
  value = "storage.googleapis.com"
}

output "display" {
  value = "Data Access audit logs (DATA_READ, DATA_WRITE) enabled for storage.googleapis.com"
}

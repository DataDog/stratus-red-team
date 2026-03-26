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
  resource_prefix = "stratus-red-team-wif"
}

data "google_project" "current" {}

resource "random_string" "suffix" {
  length    = 8
  special   = false
  min_lower = 8
}

# Target service account that an attacker would impersonate via WIF.
# In a real environment an adversary would target an existing high-privilege SA;
# here we create a dedicated one so the attack is self-contained.
resource "google_service_account" "sa" {
  account_id   = "${local.resource_prefix}-${random_string.suffix.result}"
  display_name = "Stratus Red Team WIF Target SA"
}

output "pool_id" {
  value = "${local.resource_prefix}-${random_string.suffix.result}"
}

output "sa_email" {
  value = google_service_account.sa.email
}

output "project_number" {
  value = data.google_project.current.number
}

output "display" {
  value = "Service account ${google_service_account.sa.email} targeted by WIF pool ${local.resource_prefix}-${random_string.suffix.result}"
}

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
  num_secrets     = 20
  resource_prefix = "stratus-red-team-retrieve-secret"
}

resource "random_string" "secrets" {
  count     = local.num_secrets
  length    = 16
  min_lower = 16
}

resource "google_secret_manager_secret" "secrets" {
  count = local.num_secrets
  secret_id  = "${local.resource_prefix}-${count.index}"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "secrets" {
  count = local.num_secrets
  secret = google_secret_manager_secret.secrets[count.index].name
  secret_data = random_string.secrets[count.index].result
}


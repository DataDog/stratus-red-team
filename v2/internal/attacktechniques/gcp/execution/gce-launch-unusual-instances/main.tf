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
  resource_prefix = "stratus-red-team-lui"
  region          = "us-east1"
}

resource "random_string" "suffix" {
  special = false
  length  = 16
  min_lower = 16
}

data "google_project" "current" { }

data "google_client_openid_userinfo" "whoami" { }

data "google_compute_zones" "available" {
  region  = local.region
}

resource "google_service_account" "launcher" {
  account_id   = "stratus-sa-${random_string.suffix.result}"
  display_name = "Instance Launcher (Stratus Red Team)"
}

resource "google_project_iam_binding" "binding" {
  project = data.google_project.current.project_id
  role    = "roles/compute.viewer"
  members = [ "serviceAccount:${google_service_account.launcher.email}" ]
}

resource "google_project_iam_binding" "impersonator" {
  project = data.google_project.current.project_id
  role    = "roles/iam.serviceAccountTokenCreator"
  members = [ "user:${data.google_client_openid_userinfo.whoami.email}" ]
}

resource "google_compute_network" "network" {
  name  = "${local.resource_prefix}-vpc-${random_string.suffix.result}"
  routing_mode  = "REGIONAL"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${local.resource_prefix}-subnet-${random_string.suffix.result}"
  ip_cidr_range = "10.10.1.0/24"
  network       = google_compute_network.network.id
  region        = local.region
}

output "sa_email" {
  value = google_service_account.launcher.email
}

output "sa_id" {
  value = google_service_account.launcher.id
}

output "zone" {
  value = data.google_compute_zones.available.names[0]
}

output "network" {
  value = google_compute_network.network.id
}

output "subnet" {
  value = google_compute_subnetwork.subnet.id
}

output "display" {
  value = format("Service account '%s' ready for use", google_service_account.launcher.email)
}
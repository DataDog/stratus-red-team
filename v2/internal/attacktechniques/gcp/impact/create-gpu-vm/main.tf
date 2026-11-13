terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
  }
}

locals {
  resource_prefix = "stratus-red-team-gpu"
}

resource "google_compute_network" "gpu" {
  name                    = "${local.resource_prefix}-vpc-${var.correlation.short}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "gpu" {
  name          = "${local.resource_prefix}-subnet-${var.correlation.short}"
  ip_cidr_range = "10.10.0.0/24"
  region        = "us-central1"
  network       = google_compute_network.gpu.id
}

output "suffix" {
  value = var.correlation.short
}

output "network_self_link" {
  value = google_compute_network.gpu.self_link
}

output "subnetwork_self_link" {
  value = google_compute_subnetwork.gpu.self_link
}

output "display" {
  value = "Ready to create a GPU-enabled GCE instance"
}

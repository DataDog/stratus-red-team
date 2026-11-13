terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
  }
}


locals {
  subnet_cidrs = {
    "us-central1"  = "10.0.0.0/24"
    "us-east1"     = "10.0.1.0/24"
    "us-west1"     = "10.0.2.0/24"
    "europe-west1" = "10.0.3.0/24"
    "europe-west2" = "10.0.4.0/24"
    "asia-east1"   = "10.0.5.0/24"
  }
}

resource "google_compute_network" "target" {
  name                    = "stratus-red-team-${var.correlation.short}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "target" {
  for_each = local.subnet_cidrs

  name          = "stratus-red-team-${var.correlation.short}-${each.key}"
  ip_cidr_range = each.value
  region        = each.key
  network       = google_compute_network.target.self_link
}

output "suffix" {
  value = var.correlation.short
}

output "network" {
  value = google_compute_network.target.self_link
}

output "subnetworks" {
  value = jsonencode({ for region, subnet in google_compute_subnetwork.target : region => subnet.self_link })
}

output "display" {
  value = "Ready to create GCE instances in multiple zones"
}

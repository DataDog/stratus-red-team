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
  resource_prefix = "stratus-red-team-rvfl" # stratus red team remove vpc flow logs
}

resource "random_string" "suffix" {
  length    = 8
  special   = false
  min_lower = 8
}

resource "google_compute_network" "vpc" {
  name                    = "${local.resource_prefix}-vpc-${random_string.suffix.result}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${local.resource_prefix}-subnet-${random_string.suffix.result}"
  ip_cidr_range = "10.10.0.0/24"
  region        = "us-central1"
  network       = google_compute_network.vpc.id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

output "subnet_name" {
  value = google_compute_subnetwork.subnet.name
}

output "region" {
  value = google_compute_subnetwork.subnet.region
}

output "display" {
  value = format("Subnet %s in region %s with VPC flow logs enabled", google_compute_subnetwork.subnet.name, google_compute_subnetwork.subnet.region)
}

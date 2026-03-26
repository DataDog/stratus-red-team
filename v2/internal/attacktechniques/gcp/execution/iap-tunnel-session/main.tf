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
  resource_prefix = "stratus-red-team-its" # iap tunnel session
}

resource "random_string" "suffix" {
  length    = 8
  special   = false
  min_lower = 8
}

resource "google_compute_network" "vpc" {
  name                    = "${local.resource_prefix}-vpc-${random_string.suffix.result}"
  auto_create_subnetworks = true
}

resource "google_compute_instance" "instance" {
  name         = "${local.resource_prefix}-${random_string.suffix.result}"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = google_compute_network.vpc.self_link
  }

  tags = ["stratus-red-team"]
}

# Represents the attacker-controlled service account that will be granted
# IAP tunnel access. In a real attack, this would be a SA in an external project.
resource "google_service_account" "attacker_sa" {
  account_id   = "${local.resource_prefix}-${random_string.suffix.result}"
  display_name = "Stratus Red Team - IAP Backdoor SA"
}

output "instance_name" {
  value = google_compute_instance.instance.name
}

output "zone" {
  value = google_compute_instance.instance.zone
}

output "attacker_sa_email" {
  value = google_service_account.attacker_sa.email
}

output "display" {
  value = format("GCE instance %s, attacker SA %s ready for IAP tunnel access simulation", google_compute_instance.instance.name, google_service_account.attacker_sa.email)
}

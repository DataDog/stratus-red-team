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
  resource_prefix = "stratus-red-team-mgss" # modify gce startup script
}

resource "random_string" "suffix" {
  length    = 8
  special   = false
  min_lower = 8
}

resource "google_service_account" "instance_sa" {
  account_id   = "${local.resource_prefix}-${random_string.suffix.result}"
  display_name = "Stratus Red Team - Modify GCE Startup Script"
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

  metadata = {
    startup-script = "#!/bin/bash\necho 'Legitimate startup script'"
  }

  service_account {
    email  = google_service_account.instance_sa.email
    scopes = ["cloud-platform"]
  }
}

output "instance_name" {
  value = google_compute_instance.instance.name
}

output "zone" {
  value = google_compute_instance.instance.zone
}

output "display" {
  value = format("GCE instance %s in zone %s", google_compute_instance.instance.name, google_compute_instance.instance.zone)
}

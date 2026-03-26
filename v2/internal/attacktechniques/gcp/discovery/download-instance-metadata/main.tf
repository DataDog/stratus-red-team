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
  resource_prefix = "stratus-red-team-dim" # download instance metadata
  zone            = "us-central1-a"
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
  zone         = local.zone

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  # No access_config means no external IP — the instance is not publicly reachable.
  network_interface {
    network = google_compute_network.vpc.self_link
  }

  metadata = {
    # Simulates a bootstrap script that embeds credentials, a common misconfiguration
    # that attackers discover via the Compute API's instance metadata endpoint.
    startup-script = "#!/bin/bash\n# Database configuration\nexport DB_PASSWORD=S3cr3tP4ssw0rd!\nexport API_TOKEN=ghp_FakeGitHubToken12345\nmysql -h 10.0.0.1 -u admin -pS3cr3tP4ssw0rd!"
  }
}

output "instance_name" {
  value = google_compute_instance.instance.name
}

output "zone" {
  value = local.zone
}

output "display" {
  value = format("GCE instance %s in zone %s", google_compute_instance.instance.name, local.zone)
}

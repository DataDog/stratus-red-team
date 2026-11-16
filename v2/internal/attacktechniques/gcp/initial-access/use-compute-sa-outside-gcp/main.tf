terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
  }
}

data "google_compute_default_service_account" "default" {}

resource "google_compute_network" "vpc" {
  name                    = "stratus-red-team-csa-vpc-${var.correlation.short}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "stratus-red-team-csa-subnet-${var.correlation.short}"
  ip_cidr_range = "10.10.0.0/24"
  region        = "us-east1"
  network       = google_compute_network.vpc.id
}

resource "google_compute_instance" "target" {
  name         = "stratus-red-team-csa-${var.correlation.short}"
  machine_type = "e2-micro"
  zone         = "us-east1-b"

  boot_disk {
    initialize_params {
      image = "projects/debian-cloud/global/images/family/debian-12"
      size  = 10
    }
  }

  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.subnet.id
  }

  metadata = {
    startup-script = <<-SCRIPT
#!/bin/bash
fetch_token() {
  TOKEN=$(curl -sf -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
  if [ -n "$TOKEN" ]; then
    echo "STRATUS_TOKEN_START$${TOKEN}STRATUS_TOKEN_END" > /dev/ttyS0
    return 0
  fi
  return 1
}

# Retry initial fetch every 5 seconds for up to 2 minutes
for i in $(seq 1 24); do
  fetch_token && break
  sleep 5
done

# Background refresh loop every 30 minutes so the token stays fresh
while true; do sleep 1800; fetch_token; done &
SCRIPT
  }

  service_account {
    email  = data.google_compute_default_service_account.default.email
    scopes = ["cloud-platform"]
  }
}

output "sa_email" {
  value = data.google_compute_default_service_account.default.email
}

output "instance_name" {
  value = google_compute_instance.target.name
}

output "zone" {
  value = google_compute_instance.target.zone
}

output "display" {
  value = format("GCE instance %s with default compute service account ready", google_compute_instance.target.name)
}

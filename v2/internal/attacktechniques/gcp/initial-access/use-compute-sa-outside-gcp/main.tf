terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
  }
}

data "google_compute_default_service_account" "default" {}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "google_compute_instance" "target" {
  name         = "stratus-red-team-csa-${random_string.suffix.result}"
  machine_type = "e2-micro"
  zone         = "us-east1-b"

  boot_disk {
    initialize_params {
      image = "projects/debian-cloud/global/images/family/debian-12"
      size  = 10
    }
  }

  network_interface {
    network = "default"
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

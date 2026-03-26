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
  resource_prefix = "stratus-red-team-occr" # os config run command
}

resource "random_string" "suffix" {
  length    = 8
  special   = false
  min_lower = 8
}

resource "google_service_account" "instance_sa" {
  account_id   = "${local.resource_prefix}-${random_string.suffix.result}"
  display_name = "Stratus Red Team - OS Config Run Command"
}

resource "google_compute_network" "vpc" {
  name                    = "${local.resource_prefix}-vpc-${random_string.suffix.result}"
  auto_create_subnetworks = false
}

# Private Google Access lets the instance reach Google APIs (including OS Config)
# without a public IP, which is required for the OS Config agent to phone home.
resource "google_compute_subnetwork" "subnet" {
  name                     = "${local.resource_prefix}-subnet-${random_string.suffix.result}"
  ip_cidr_range            = "10.0.0.0/24"
  region                   = "us-central1"
  network                  = google_compute_network.vpc.self_link
  private_ip_google_access = true
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
    subnetwork = google_compute_subnetwork.subnet.self_link
  }

  # enable-osconfig activates the OS Config agent on the instance.
  # The OS Config agent is pre-installed on Debian 11 images but must be
  # explicitly enabled via metadata for the OSPolicyAssignment API to work.
  metadata = {
    enable-osconfig = "TRUE"
  }

  service_account {
    email  = google_service_account.instance_sa.email
    scopes = ["cloud-platform"]
  }

  labels = {
    "stratus-red-team" = "true"
  }
}

output "instance_name" {
  value = google_compute_instance.instance.name
}

output "zone" {
  value = google_compute_instance.instance.zone
}

output "display" {
  value = format("GCE instance %s with OS Config agent enabled", google_compute_instance.instance.name)
}

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
  resource_prefix = "stratus-red-team-rwa"
  region          = "us-east1"
  instance_type   = "n2-standard-2"
  image           = "windows-cloud/windows-2016"
}

resource "random_string" "suffix" {
  special = false
  length  = 16
  min_lower = 16
}

data "google_compute_zones" "available" {
  region = local.region
}

resource "google_compute_network" "network" {
  name  = "${local.resource_prefix}-vpc-${random_string.suffix.result}"
  routing_mode = "REGIONAL"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${local.resource_prefix}-subnet-${random_string.suffix.result}"
  ip_cidr_range = "10.10.1.0/24"
  network       = google_compute_network.network.id
  region        = local.region
}

resource "google_compute_firewall" "firewall" {
  name = "${local.resource_prefix}-firewall-${random_string.suffix.result}"
  network = google_compute_network.network.id

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["rdp-access"]
}

resource "google_compute_instance" "target" {
  name         = "${local.resource_prefix}-vm-${random_string.suffix.result}"
  machine_type = local.instance_type
  zone         = data.google_compute_zones.available.names[0]
  hostname     = "target-windows-${random_string.suffix.result}.stratus.local"
  tags         = ["rdp-access"]

  boot_disk {
    initialize_params {
      image = local.image
    }
  }

  network_interface {
    network = google_compute_network.network.id
    subnetwork = google_compute_subnetwork.subnet.id

    access_config { }
  }
}

output "display" {
  value = format("Windows instance (hostname: %s, ip: %s) is ready", 
    google_compute_instance.target.name,
    google_compute_instance.target.network_interface.0.access_config.0.nat_ip
  )  
}

output "zone" {
  value = data.google_compute_zones.available.names[0]
}

output "instance_name" {
  value = google_compute_instance.target.name
}

output "instance_ip" {
  value = google_compute_instance.target.network_interface.0.access_config.0.nat_ip
}
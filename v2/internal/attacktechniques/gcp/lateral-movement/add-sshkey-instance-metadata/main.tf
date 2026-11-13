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
  resource_prefix = "stratus-red-team-ssh-key"
  region          = "us-east1"
  instance_type   = "f1-micro"
  image           = "projects/debian-cloud/global/images/family/debian-12"
}


data "google_compute_zones" "available" {
  region = local.region
}

resource "google_compute_network" "network" {
  name                    = "${local.resource_prefix}-vpc-${var.correlation.short}"
  routing_mode            = "REGIONAL"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${local.resource_prefix}-subnet-${var.correlation.short}"
  ip_cidr_range = "10.10.1.0/24"
  network       = google_compute_network.network.id
  region        = local.region
}

resource "google_compute_firewall" "firewall" {
  name    = "${local.resource_prefix}-firewall-${var.correlation.short}"
  network = google_compute_network.network.id
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["ssh-access"]
}

resource "google_compute_instance" "target" {
  name         = "${local.resource_prefix}-vm-${var.correlation.short}"
  machine_type = local.instance_type
  zone         = data.google_compute_zones.available.names[0]
  hostname     = "target-${var.correlation.short}.stratus.local"
  tags         = ["ssh-access"]

  boot_disk {
    initialize_params {
      image = local.image
    }
  }

  network_interface {
    network    = google_compute_network.network.id
    subnetwork = google_compute_subnetwork.subnet.id

    access_config {}
  }
}

output "display" {
  value = format("Linux instance (hostname: %s, ip: %s) is ready",
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
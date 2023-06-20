terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.28.0"
    }
  }
}

locals {
  disk-name = "stratus-red-team-victim-disk"
}


resource "google_compute_disk" "disk" {
  name = local.disk-name
  size = 10 # minimum size is 10GB
  zone = "us-central1-a"
}

output "disk_name" {
  value = google_compute_disk.disk.name
}

output "zone" {
  value = google_compute_disk.disk.zone
}

output "display" {
  value = format("Compute disk %s is ready", google_compute_disk.disk.name)
}
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
  snapshot-name = "stratus-red-team-victim-snapshot"
  zone = "us-central1-a"
}

resource "google_compute_disk" "this" {
  name = local.disk-name
  size = 10 # minimum size is 10GB
  zone = local.zone
}

resource "google_compute_snapshot" "this" {
  name = local.snapshot-name
  source_disk = google_compute_disk.this.id
  zone = local.zone
}

output "snapshot_name" {
  value = google_compute_snapshot.this.name
}

output "zone" {
  value = google_compute_disk.this.zone
}

output "display" {
  value = format("Compute snapshot %s is ready", google_compute_snapshot.this.name)
}

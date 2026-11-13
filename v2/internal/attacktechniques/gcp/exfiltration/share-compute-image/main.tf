terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.28.0"
    }
  }
}

locals {
  disk-name  = "stratus-red-team-victim-image-disk-${var.correlation.short}"
  image-name = "stratus-red-team-victim-image-${var.correlation.short}"
  zone       = "us-east1-b"
}

data "google_compute_image" "debian" {
  family  = "debian-12"
  project = "debian-cloud"
}

resource "google_compute_disk" "this" {
  name  = local.disk-name
  type  = "pd-standard"
  size  = 10
  zone  = local.zone
  image = data.google_compute_image.debian.self_link
}

resource "google_compute_image" "this" {
  name        = local.image-name
  source_disk = google_compute_disk.this.self_link
}

output "image_name" {
  value = google_compute_image.this.name
}

output "display" {
  value = format("Compute image %s is ready", google_compute_image.this.name)
}

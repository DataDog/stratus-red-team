terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.28.0"
    }
  }
}

locals {
  region     = coalesce(data.google_client_config.this.region, "us-east1")
  disk-name  = "stratus-red-team-victim-image-disk-${var.correlation.short}"
  image-name = "stratus-red-team-victim-image-${var.correlation.short}"
}

data "google_compute_image" "debian" {
  family  = "debian-12"
  project = "debian-cloud"
}

data "google_client_config" "this" {}

data "google_compute_zones" "available" {
  region = local.region
}

resource "google_compute_disk" "this" {
  name  = local.disk-name
  type  = "pd-standard"
  size  = 10
  zone  = data.google_compute_zones.available.names[0]
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

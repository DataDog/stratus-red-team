terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.28.0"
    }
  }
}

locals {
  image-name = "stratus-red-team-victim-image"
}

resource "google_compute_image" "this" {
  family = "debian-11"
}

output "image_name" {
  value = google_compute_image.this.name
}

output "display" {
  value = format("Compute image %s is ready", google_compute_image.this.name)
}

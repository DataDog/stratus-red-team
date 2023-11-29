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
  name = local.image-name

  raw_disk {
    source = "https://storage.googleapis.com/bosh-gce-raw-stemcells/bosh-stemcell-97.98-google-kvm-ubuntu-xenial-go_agent-raw-1557960142.tar.gz"
  }
}

output "image_name" {
  value = google_compute_image.this.name
}

output "display" {
  value = format("Compute image %s is ready", google_compute_image.this.name)
}

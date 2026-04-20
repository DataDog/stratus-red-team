terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

output "suffix" {
  value = random_string.suffix.result
}

output "display" {
  value = "Ready to create a GPU-enabled GCE instance"
}

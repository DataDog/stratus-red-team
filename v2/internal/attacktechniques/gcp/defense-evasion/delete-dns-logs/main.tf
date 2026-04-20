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
  resource_prefix = "stratus-red-team-ddl" # stratus red team delete dns logs
}

resource "random_string" "suffix" {
  length    = 8
  special   = false
  min_lower = 8
}

resource "google_dns_policy" "logging_policy" {
  name           = "${local.resource_prefix}-policy-${random_string.suffix.result}"
  enable_logging = true

  networks {
    network_url = google_compute_network.vpc.id
  }
}

resource "google_compute_network" "vpc" {
  name                    = "${local.resource_prefix}-vpc-${random_string.suffix.result}"
  auto_create_subnetworks = false
}

output "policy_name" {
  value = google_dns_policy.logging_policy.name
}

output "display" {
  value = format("Cloud DNS policy %s with query logging enabled", google_dns_policy.logging_policy.name)
}

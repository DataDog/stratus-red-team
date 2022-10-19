terraform {
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.3.2"
    }
  }
}

resource "random_string" "suffix" {
  length      = 4
  special     = false
  min_lower   = 3
  min_numeric = 3
}

output "service_account_name" {
  value = "stratus-red-team-admin-sa-${random_string.suffix.result}"
}
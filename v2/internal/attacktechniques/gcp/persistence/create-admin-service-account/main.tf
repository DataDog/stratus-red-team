terraform {
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.3.2"
    }
  }
}

resource "random_string" "suffix" {
  length      = 6
  special     = false
  min_lower   = 3
  min_numeric = 3
}

output "service_account_name" {
  value = format("stratus-red-team-sa-%s", random_string.suffix.result)
}
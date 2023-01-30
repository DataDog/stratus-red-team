terraform {
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.3.2"
    }
  }
}

locals {
  resource_prefix = "stratus-red-team-casa" # stratus red team create admin service account
}

resource "random_string" "suffix" {
  length    = 4
  special   = false
  min_lower = 4
}

output "service_account_name" {
  value = format("%s-sa-%s", local.resource_prefix, random_string.suffix.result)
}

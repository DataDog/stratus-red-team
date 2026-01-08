terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0.0"
    }
  }
}

provider "azurerm" {
  features {}
}

locals {
  resource_prefix = "stratus-red-team-storage-public-access"
}

# TODO: Add resources for:
# - Azure Storage Account
# - Blob Container (private by default)
# - Sample blob data

output "resource_group" {
  value = "TODO"
}

output "storage_account_name" {
  value = "TODO"
}

output "container_name" {
  value = "TODO"
}

output "display" {
  value = "Azure Storage account and private blob container created"
}

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
  resource_prefix = "stratus-red-team-storage-sas-export"
}

# TODO: Add prerequisite resources

output "display" {
  value = "Technique prerequisites deployed"
}

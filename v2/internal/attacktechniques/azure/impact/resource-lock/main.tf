terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.57.0"
    }
  }
}

provider "azurerm" {
  features {}
  storage_use_azuread      = true
}

resource "random_string" "suffix" {
  length  = 4
  special = false
  upper   = false
}

locals {
  resource_prefix = "stratus-red-team-lock"
  # Storage account names must be between 3 and 24 characters in length and use numbers and lower-case letters only
  storage_account_name = "stratusredteam${random_string.suffix.result}"
  container_name       = "private-data"
}

resource "azurerm_resource_group" "rg" {
  name     = "${local.resource_prefix}-storage-${random_string.suffix.result}"
  location = "West US"
}

resource "azurerm_storage_account" "storage" {
  name                     = local.storage_account_name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Resource lock must be Resource Group level to prevent destruction race conditions
resource "azurerm_management_lock" "rg_lock" {
  name       = "stratus-storage-lock-${random_string.suffix.result}"
  scope      = azurerm_resource_group.rg.id
  lock_level = "ReadOnly"
  notes      = "Stratus Storage resource lock"
  depends_on = [azurerm_storage_account.storage]
}

output "display" {
  value = format("Azure Storage account %s with resource lock ready", azurerm_storage_account.storage.name)
}

output "storage_account_name" {
  value = azurerm_storage_account.storage.name
}

output "resource_group" {
  value = azurerm_resource_group.rg.name
}

output "resource_lock" {
  value = azurerm_management_lock.rg_lock.name
}
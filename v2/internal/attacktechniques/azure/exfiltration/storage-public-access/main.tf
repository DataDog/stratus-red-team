terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.81.0"
    }
  }
}

provider "azurerm" {
  features {}
}


locals {
  resource_prefix = "stratus-red-team-storage"
  # Storage account names must be between 3 and 24 characters in length and use numbers and lower-case letters only
  storage_account_name = "stratusredteam${var.correlation.short}"
  container_name       = "private-data"
}

resource "azurerm_resource_group" "rg" {
  name     = "${local.resource_prefix}-storage-${var.correlation.short}"
  location = "West US"
}

resource "azurerm_storage_account" "storage" {
  name                     = local.storage_account_name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # Set storage account to disable blob anonymous access
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "container" {
  name                 = local.container_name
  storage_account_name = azurerm_storage_account.storage.name
  # Set container to private access
  container_access_type = "private"
}

# Empty test file to simulate file access
resource "azurerm_storage_blob" "sample_file" {
  name                   = "sample-file.txt"
  storage_account_name   = azurerm_storage_account.storage.name
  storage_container_name = azurerm_storage_container.container.name
  type                   = "Block"
}

output "display" {
  value = format("Azure Storage account %s with container %s ready", azurerm_storage_account.storage.name, azurerm_storage_container.container.name)
}

output "storage_account_name" {
  value = azurerm_storage_account.storage.name
}

output "container_name" {
  value = azurerm_storage_container.container.name
}

output "resource_group" {
  value = azurerm_resource_group.rg.name
}

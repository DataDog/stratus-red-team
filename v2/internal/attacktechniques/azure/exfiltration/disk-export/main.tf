terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.8.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "random_string" "suffix" {
  length  = 4
  special = false
  upper   = false
}

resource "azurerm_resource_group" "rg" {
  name     = "stratus-red-team-disk-export-rg-${random_string.suffix.result}"
  location = "West US"
}

resource "azurerm_managed_disk" "disk" {
  name                 = "stratus-red-team-disk-export-disk"
  location             = azurerm_resource_group.rg.location
  resource_group_name  = azurerm_resource_group.rg.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = "1"
}

output "disk_name" {
  value = azurerm_managed_disk.disk.name
}

output "resource_group_name" {
  value = azurerm_resource_group.rg.name
}

output "display" {
  value = format("Disk %s ready in resource group %s", azurerm_managed_disk.disk.name, azurerm_resource_group.rg.name)
}

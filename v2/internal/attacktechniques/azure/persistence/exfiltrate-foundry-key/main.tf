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


resource "azurerm_resource_group" "rg" {
  name     = "stratus-red-team-foundry-rg-${var.correlation.short}"
  location = "West US"
}

resource "azurerm_cognitive_account" "foundry" {
  name                  = "stratus-rt-${var.correlation.short}"
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  kind                  = "AIServices"
  sku_name              = "S0"
  local_auth_enabled    = false
  custom_subdomain_name = "stratus-rt-${var.correlation.short}"
}

output "cognitive_account_name" {
  value = azurerm_cognitive_account.foundry.name
}

output "resource_group_name" {
  value = azurerm_resource_group.rg.name
}

output "display" {
  value = format("Azure AI Foundry account %s ready in resource group %s (local auth disabled)", azurerm_cognitive_account.foundry.name, azurerm_resource_group.rg.name)
}

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
  length  = 8
  special = false
  upper   = false
}

resource "azurerm_resource_group" "rg" {
  name     = "stratus-red-team-asp-cred-rg-${random_string.suffix.result}"
  # West US 2 is used instead of West US: App Service plan quota in smaller
  # regions such as West US is frequently 0, causing deployment failures.
  # Larger regions like West US 2 have more spare capacity.
  location = "West US 2"
}

resource "azurerm_service_plan" "plan" {
  name                = "stratus-red-team-asp-cred-plan"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  os_type             = "Linux"
  sku_name            = "B1"
}

resource "azurerm_linux_web_app" "app" {
  name                = "srt-asp-cred-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_service_plan.plan.location
  service_plan_id     = azurerm_service_plan.plan.id

  site_config {}
}

output "app_service_name" {
  value = azurerm_linux_web_app.app.name
}

output "resource_group_name" {
  value = azurerm_resource_group.rg.name
}

output "display" {
  value = format("App Service %s ready in resource group %s", azurerm_linux_web_app.app.name, azurerm_resource_group.rg.name)
}

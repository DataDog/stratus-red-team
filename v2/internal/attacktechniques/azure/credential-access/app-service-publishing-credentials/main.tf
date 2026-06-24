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
  location = "West US"
}

resource "azurerm_service_plan" "plan" {
  name                = "stratus-red-team-asp-cred-plan"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  os_type             = "Linux"
  # Free tier: runs on shared infrastructure, so it does not draw from the
  # subscription's regional vCPU quota. The technique only needs the App
  # Service to exist to read its publishing credentials, not dedicated compute.
  sku_name            = "F1"
}

resource "azurerm_linux_web_app" "app" {
  name                = "srt-asp-cred-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_service_plan.plan.location
  service_plan_id     = azurerm_service_plan.plan.id

  site_config {
    # always_on is not supported on the Free tier and defaults to true for
    # Linux web apps, so it must be disabled explicitly.
    always_on = false
  }
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

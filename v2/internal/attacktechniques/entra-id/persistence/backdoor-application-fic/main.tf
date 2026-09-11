terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "2.53.1"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.81.0"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azuread_client_config" "current" {}
data "azurerm_subscription" "current" {}


resource "azuread_application" "app" {
  display_name = "Stratus Red Team FIC application ${var.correlation.short}"
}

resource "azuread_service_principal" "sp" {
  client_id                    = azuread_application.app.client_id
  app_role_assignment_required = true
}

resource "azuread_directory_role" "directory-readers" {
  display_name = "Directory Readers"
}

resource "azuread_directory_role_assignment" "role" {
  role_id             = azuread_directory_role.directory-readers.template_id
  principal_object_id = azuread_service_principal.sp.object_id
}

# Resource group for the OIDC storage account
resource "azurerm_resource_group" "oidc" {
  name     = "stratus-fic-app-${var.correlation.short}"
  location = "westus"
}

# Storage account to host the malicious OIDC provider metadata
resource "azurerm_storage_account" "oidc" {
  name                            = "stratusficapp${var.correlation.short}"
  resource_group_name             = azurerm_resource_group.oidc.name
  location                        = azurerm_resource_group.oidc.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = true
}

# Assign Storage Blob Data Contributor to the current user for data plane access (so Go can use RBAC operations)
resource "azurerm_role_assignment" "storage_blob_data_contributor" {
  scope                = azurerm_storage_account.oidc.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azuread_client_config.current.object_id
}

output "object_id" {
  value = azuread_application.app.object_id
}

output "app_id" {
  value = azuread_application.app.application_id
}

output "storage_account_name" {
  value = azurerm_storage_account.oidc.name
}

output "resource_group_name" {
  value = azurerm_resource_group.oidc.name
}

output "blob_service_url" {
  value = azurerm_storage_account.oidc.primary_blob_endpoint
}

output "random_suffix" {
  value = var.correlation.short
}

output "display" {
  value = format("Victim application '%s' ready", azuread_application.app.display_name)
}
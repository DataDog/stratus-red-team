terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "2.53.1"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.8.0"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azuread_client_config" "current" {}
data "azurerm_subscription" "current" {}

resource "random_string" "suffix" {
  length  = 4
  special = false
  upper   = false
}

# Resource group for the managed identity
resource "azurerm_resource_group" "mi" {
  name     = "stratus-fic-mi-${random_string.suffix.result}"
  location = "eastus"
}

# Victim user-assigned managed identity
resource "azurerm_user_assigned_identity" "victim" {
  name                = "stratus-victim-mi-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.mi.name
  location            = azurerm_resource_group.mi.location
}

# Assign Directory Readers role to the managed identity at tenant level
resource "azuread_directory_role" "directory-readers" {
  display_name = "Directory Readers"
}

resource "azuread_directory_role_assignment" "role" {
  role_id             = azuread_directory_role.directory-readers.template_id
  principal_object_id = azurerm_user_assigned_identity.victim.principal_id
}

# Resource group for the OIDC storage account
resource "azurerm_resource_group" "oidc" {
  name     = "stratus-fic-oidc-${random_string.suffix.result}"
  location = "eastus"
}

# Storage account to host the malicious OIDC provider metadata
resource "azurerm_storage_account" "oidc" {
  name                            = "stratusoidc${random_string.suffix.result}"
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

output "managed_identity_id" {
  value = azurerm_user_assigned_identity.victim.id
}

output "managed_identity_client_id" {
  value = azurerm_user_assigned_identity.victim.client_id
}

output "managed_identity_principal_id" {
  value = azurerm_user_assigned_identity.victim.principal_id
}

output "managed_identity_name" {
  value = azurerm_user_assigned_identity.victim.name
}

output "resource_group_name" {
  value = azurerm_resource_group.mi.name
}

output "storage_account_name" {
  value = azurerm_storage_account.oidc.name
}

output "storage_resource_group_name" {
  value = azurerm_resource_group.oidc.name
}

output "blob_service_url" {
  value = azurerm_storage_account.oidc.primary_blob_endpoint
}

output "random_suffix" {
  value = random_string.suffix
}

output "display" {
  value = format("Victim managed identity '%s' ready", azurerm_user_assigned_identity.victim.name)
}

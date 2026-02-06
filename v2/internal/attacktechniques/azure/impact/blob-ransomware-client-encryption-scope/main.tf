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
  length  = 6
  special = false
  upper   = false
}

resource "random_string" "keyvault_suffix" {
  length  = 8
  special = false
  upper   = false
}

locals {
  resource_prefix      = "stratusrt"
  storage_account_name = "${local.resource_prefix}${random_string.suffix.result}"
  key_vault_name       = "${local.resource_prefix}${random_string.keyvault_suffix.result}"
  num_containers       = 5
}

resource "azurerm_resource_group" "rg" {
  name     = "stratus-red-team-blob-encryption-rg-${random_string.suffix.result}"
  location = "West US"
}

data "azurerm_client_config" "current" {}

resource "azurerm_storage_account" "storage" {
  name                     = local.storage_account_name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_key_vault" "kv" {
  name                       = local.key_vault_name
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  enable_rbac_authorization  = true
}

resource "azurerm_role_assignment" "storage_keyvault_crypto" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_storage_account.storage.identity[0].principal_id
}


resource "azurerm_storage_container" "containers" {
  count                 = local.num_containers
  name                  = "container-${count.index + 1}"
  storage_account_name  = azurerm_storage_account.storage.name
  container_access_type = "private"
}

output "display" {
  value = format("Storage account %s with %d containers ready. Key Vault %s ready. Blobs will be created during detonation.", azurerm_storage_account.storage.name, local.num_containers, local.key_vault_name)
}

output "storage_account_name" {
  value = azurerm_storage_account.storage.name
}

output "resource_group_name" {
  value = azurerm_resource_group.rg.name
}

output "key_vault_name" {
  value = local.key_vault_name
}

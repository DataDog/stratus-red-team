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

locals {
  resource_prefix = "stratus-red-team-shareable-link"
}

data "azurerm_client_config" "current" {
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Random
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #

resource "random_string" "lab_name" {
  length  = 4
  special = false
  upper   = false
}

resource "random_password" "password" {
  length           = 64
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Resource Group
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #

resource "azurerm_resource_group" "lab_environment" {
  name     = "${local.resource_prefix}-rg-${random_string.lab_name.result}"
  location = "West US"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Networking Resources
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #

resource "azurerm_virtual_network" "lab_vnet" {
  name                = "${local.resource_prefix}-vnet-${random_string.lab_name.result}"
  address_space       = ["10.0.0.0/24"]
  location            = azurerm_resource_group.lab_environment.location
  resource_group_name = azurerm_resource_group.lab_environment.name
}

resource "azurerm_subnet" "bastion_subnet" {
  # Required naming for deployment of Azure Bastion
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.lab_environment.name
  virtual_network_name = azurerm_virtual_network.lab_vnet.name
  address_prefixes     = ["10.0.0.0/27"]
}

resource "azurerm_subnet" "lab_subnet" {
  name                 = "${local.resource_prefix}-subnet-${random_string.lab_name.result}"
  resource_group_name  = azurerm_resource_group.lab_environment.name
  virtual_network_name = azurerm_virtual_network.lab_vnet.name
  address_prefixes     = ["10.0.0.32/27"]
}

resource "azurerm_public_ip" "lab_pip" {
  name                = "${local.resource_prefix}-pip-${random_string.lab_name.result}"
  location            = azurerm_resource_group.lab_environment.location
  resource_group_name = azurerm_resource_group.lab_environment.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "lab_nic" {
  name                = "${local.resource_prefix}-nic-${random_string.lab_name.result}"
  location            = azurerm_resource_group.lab_environment.location
  resource_group_name = azurerm_resource_group.lab_environment.name

  ip_configuration {
    name                          = "${local.resource_prefix}-ip-${random_string.lab_name.result}"
    subnet_id                     = azurerm_subnet.lab_subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Virtual Machine Resources
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
resource "azurerm_windows_virtual_machine" "lab_windows_vm" {
  name                = "srt-vm-bsl" # 15 character limit: stratus red team - vm - bastion shareable link
  resource_group_name = azurerm_resource_group.lab_environment.name
  location            = azurerm_resource_group.lab_environment.location
  size                = "Standard_F2"
  admin_username      = "local_admin_user"
  admin_password      = random_password.password.result
  user_data           = base64encode(random_string.lab_name.result)

  network_interface_ids = [
    azurerm_network_interface.lab_nic.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter"
    version   = "latest"
  }
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Bastion Resource
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Note: Creation/destruction of a Bastion can take 10 minutes each, see https://learn.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal
resource "azurerm_bastion_host" "bastion" {
  name                = "${local.resource_prefix}-bastion-${random_string.lab_name.result}"
  location            = azurerm_resource_group.lab_environment.location
  resource_group_name = azurerm_resource_group.lab_environment.name
  # Required for shareable link feature
  sku                    = "Standard"
  shareable_link_enabled = true

  ip_configuration {
    name                 = "${local.resource_prefix}-ipconfig-${random_string.lab_name.result}"
    subnet_id            = azurerm_subnet.bastion_subnet.id
    public_ip_address_id = azurerm_public_ip.lab_pip.id
  }
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Outputs
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
output "resource_group_name" {
  value = azurerm_resource_group.lab_environment.name
}

output "bastion_name" {
  value = azurerm_bastion_host.bastion.name
}

output "vm_id" {
  value = azurerm_windows_virtual_machine.lab_windows_vm.id
}

output "vm_name" {
  value = azurerm_windows_virtual_machine.lab_windows_vm.name
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "display" {
  value = format(
    "Bastion %s ready in resource group %s, with access to VM %s.",
    azurerm_windows_virtual_machine.lab_windows_vm.name,
    azurerm_resource_group.lab_environment.name,
    azurerm_windows_virtual_machine.lab_windows_vm.name
  )
}
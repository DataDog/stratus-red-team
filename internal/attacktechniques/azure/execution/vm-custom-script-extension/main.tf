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

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Random
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #

resource "random_string" "lab_name" {
  length  = 8
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
  name     = "rg-${random_string.lab_name.result}"
  location = "West US"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Networking Resources
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #

resource "azurerm_virtual_network" "lab_vnet" {
  name                = "vnet-${random_string.lab_name.result}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.lab_environment.location
  resource_group_name = azurerm_resource_group.lab_environment.name
}

resource "azurerm_subnet" "lab_subnet" {
  name                 = "subnet-${random_string.lab_name.result}"
  resource_group_name  = azurerm_resource_group.lab_environment.name
  virtual_network_name = azurerm_virtual_network.lab_vnet.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_interface" "lab_nic" {
  name                = "nic-${random_string.lab_name.result}"
  location            = azurerm_resource_group.lab_environment.location
  resource_group_name = azurerm_resource_group.lab_environment.name

  ip_configuration {
    name                          = "ip-${random_string.lab_name.result}"
    subnet_id                     = azurerm_subnet.lab_subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Virtual Machine Resources
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #

resource "azurerm_windows_virtual_machine" "lab_windows_vm" {
  name                = "vm-${random_string.lab_name.result}"
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

output "resource_group_name" {
  value = azurerm_resource_group.lab_environment.name
}

output "vm_instance_object_id" {
  value = azurerm_windows_virtual_machine.lab_windows_vm.id
}

output "vm_name" {
  value = azurerm_windows_virtual_machine.lab_windows_vm.name
}

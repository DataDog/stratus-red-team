terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "2.53.1"
    }
  }
}

resource "random_string" "suffix" {
  length  = 4
  special = false
  upper   = false
}

resource "azuread_application" "app" {
  display_name = "Stratus Red Team sample application ${random_string.suffix.result}"
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

output "app_object_id" {
  value = azuread_application.app.object_id
}

output "sp_app_id" {
  value = azuread_service_principal.sp.application_id
}

output "sp_object_id" {
  value = azuread_service_principal.sp.object_id
}

output "display" {
  value = format("Application '%s' ready (%s)", azuread_application.app.display_name, azuread_application.app.application_id)
}
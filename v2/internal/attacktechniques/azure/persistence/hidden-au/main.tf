terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "2.53.1"
    }
  }
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Initialize + Random
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
data "azuread_domains" "default" {
  only_initial = true
}

locals {
  resource_prefix = "srt-ehau" # stratus red team entra hidden au
  domain_name     = data.azuread_domains.default.domains.0.domain_name
}

resource "random_string" "suffix" {
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
# User Creation
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #

resource "azuread_user" "target" {
  user_principal_name = format(
    "%s@%s",
    "stratus-red-team-hidden-au-target-${random_string.suffix.result}",
    local.domain_name
  )
  password     = random_password.password.result
  display_name = "Stratus Target User - ${random_string.suffix.result}"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Role Assignments
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #

resource "azuread_directory_role" "ga" {
  display_name = "Global Administrator"
}

# Activate the PAA role ahead of time & provide role ID
resource "azuread_directory_role" "paa" {
  display_name = "Privileged Authentication Administrator"
}

# Assign privileges to target user
resource "azuread_directory_role_assignment" "target" {
  role_id             = azuread_directory_role.ga.id
  principal_object_id = azuread_user.target.id
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Output
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
output "target_user_id" {
  value = azuread_user.target.id
}

output "target_user_name" {
  value = azuread_user.target.user_principal_name
}

output "paa_role_id" {
  value = azuread_directory_role.paa.id
}

output "suffix" {
  value = random_string.suffix.result
}

output "domain" {
  value = data.azuread_domains.default.domains.0.domain_name
}

output "random_password" {
  sensitive = true
  value = random_password.password.result
}

output "display" {
  value = format("Target user %s created. PAA role initialized. GA assigned to target user.", azuread_user.target.user_principal_name)
}
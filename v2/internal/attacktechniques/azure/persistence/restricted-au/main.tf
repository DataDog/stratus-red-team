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

data "azuread_client_config" "current" {}

locals {
  domain_name = data.azuread_domains.default.domains.0.domain_name
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
resource "azuread_user" "backdoor" {
  user_principal_name = format(
    "%s@%s",
    "stratus-red-team-hidden-au-backdoor-${random_string.suffix.result}",
    local.domain_name
  )
  password     = random_password.password.result
  display_name = "Stratus Backdoor User - ${random_string.suffix.result}"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Output
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
output "backdoor_user_id" {
  value = azuread_user.backdoor.id
}

output "backdoor_user_name" {
  value = azuread_user.backdoor.user_principal_name
}

output "suffix" {
  value = random_string.suffix.result
}

output "display" {
  value = format("Backdoor user %s created", azuread_user.backdoor.user_principal_name)
}
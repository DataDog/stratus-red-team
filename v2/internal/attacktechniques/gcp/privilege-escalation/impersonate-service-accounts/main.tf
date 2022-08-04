terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.28.0"
    }
  }
}

data "google_client_openid_userinfo" "whoami" {}

locals {
  num-service-accounts = 10
}

resource "random_string" "suffix" {
  count       = local.num-service-accounts
  length      = 8
  special     = false
  min_lower   = 4
  min_numeric = 4
}

// Create N service accounts
resource "google_service_account" "service_account" {
  count       = local.num-service-accounts
  account_id  = format("stratus-red-team-%s", random_string.suffix[count.index].result)
  description = "Service account used by Stratus Red Team for gcp.privilege-escalation.impersonate-service-accounts"
}


// Allow the current user to impersonate a single of the created service accounts
resource "google_service_account_iam_policy" "iam_policy" {
  service_account_id = google_service_account.service_account[local.num-service-accounts - 1].name
  policy_data        = data.google_iam_policy.allow-impersonation.policy_data
}

data "google_iam_policy" "allow-impersonation" {
  binding {
    role = "roles/iam.serviceAccountUser"
    members = [
      format("user:%s", data.google_client_openid_userinfo.whoami.email)
    ]
  }

  binding {
    role = "roles/iam.serviceAccountTokenCreator"
    members = [
      format("user:%s", data.google_client_openid_userinfo.whoami.email)
    ]
  }
}

output "service_account_emails" {
  value = join(",", google_service_account.service_account[*].email)
}

output "display" {
  value = format("%d service accounts created and ready:\n  - %s", local.num-service-accounts, join("\n  - ", google_service_account.service_account[*].email))
}
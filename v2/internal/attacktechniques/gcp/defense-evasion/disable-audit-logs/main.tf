terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
  }
}

data "google_project" "current" {}

# Snapshot the current project IAM policy before detonation so we can
# restore the original audit config during revert. The external data
# source runs before any resource is applied, capturing the pre-stratus
# state. All parsing happens in Go — we just pass the raw JSON through.
data "external" "original_policy" {
  program = [
    "bash", "-c",
    "policy=$(gcloud projects get-iam-policy ${data.google_project.current.project_id} --format=json) || { echo 'ERROR: gcloud auth may have expired — run: gcloud auth application-default login' >&2; exit 1; }; echo \"$policy\" | jq '{policy_b64: . | @base64}'"
  ]
}

output "original_policy_b64" {
  value = data.external.original_policy.result.policy_b64
}

output "service" {
  value = "storage.googleapis.com"
}

output "display" {
  value = "Captured original audit config for storage.googleapis.com"
}

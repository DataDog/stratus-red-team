terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.3.2"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4.0"
    }
  }
}

locals {
  resource_prefix = "stratus-red-team-bcf" # backdoor cloud function
  region          = "us-central1"
}

data "google_project" "current" {}

resource "random_string" "suffix" {
  length    = 8
  special   = false
  min_lower = 8
}

resource "google_storage_bucket" "bucket" {
  name          = "${local.resource_prefix}-${random_string.suffix.result}"
  location      = "US"
  force_destroy = true
}

data "archive_file" "source" {
  type        = "zip"
  output_path = "/tmp/stratus-red-team-cf-source-bcf.zip"
  source {
    content  = "def hello_world(request):\n    return 'Hello, World!'\n"
    filename = "main.py"
  }
}

resource "google_storage_bucket_object" "source" {
  name   = "source-${data.archive_file.source.output_md5}.zip"
  bucket = google_storage_bucket.bucket.name
  source = data.archive_file.source.output_path
}

# Dedicated build service account so we don't touch the default compute SA.
# In a real attack, an adversary with sufficient permissions would create or
# reuse a service account to build and deploy their backdoored function.
resource "google_service_account" "build_sa" {
  account_id   = "${local.resource_prefix}-${random_string.suffix.result}"
  display_name = "Stratus Red Team - Cloud Function Build SA"
}

resource "google_project_iam_member" "build_sa_builder" {
  project = data.google_project.current.project_id
  role    = "roles/cloudbuild.builds.builder"
  member  = "serviceAccount:${google_service_account.build_sa.email}"
}

resource "google_project_iam_member" "build_sa_log_writer" {
  project = data.google_project.current.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.build_sa.email}"
}

# Cloud Functions v2 stages source code in a GCP-managed bucket before building.
# Custom build SAs are not granted access automatically — unlike the default
# compute SA — so we grant object viewer explicitly on that bucket.
resource "google_storage_bucket_iam_member" "build_sa_gcf_sources" {
  bucket = "gcf-v2-sources-${data.google_project.current.number}-${local.region}"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.build_sa.email}"
}

resource "google_cloudfunctions2_function" "function" {
  name     = "${local.resource_prefix}-${random_string.suffix.result}"
  location = local.region

  build_config {
    runtime         = "python311"
    entry_point     = "hello_world"
    service_account = google_service_account.build_sa.id
    source {
      storage_source {
        bucket = google_storage_bucket.bucket.name
        object = google_storage_bucket_object.source.name
      }
    }
  }

  service_config {
    min_instance_count = 0
    max_instance_count = 1
    available_memory   = "128Mi"
  }

  depends_on = [
    google_project_iam_member.build_sa_builder,
    google_project_iam_member.build_sa_log_writer,
    google_storage_bucket_iam_member.build_sa_gcf_sources,
  ]
}

output "function_name" {
  value = google_cloudfunctions2_function.function.id
}

output "display" {
  value = format("Cloud Function %s in region %s", google_cloudfunctions2_function.function.name, local.region)
}

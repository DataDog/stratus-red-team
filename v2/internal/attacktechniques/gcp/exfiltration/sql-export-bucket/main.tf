terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
    httpclient = {
      source  = "dmachard/http-client"
      version = "0.0.3"
    }
  }
}

provider "google" {
  default_labels = {
    stratus-red-team = "true"
  }
}

locals {
  resource_prefix  = "stratus-red-team-sep"
  region           = "us-east1"
  instance_tier    = "db-f1-micro"
  default_password = "StratusRedTeam"
}

resource "random_string" "suffix" {
  special = false
  length  = 16
  min_lower = 16
}

data "google_client_config" "current" { }

resource "google_sql_database_instance" "instance" {
  name = "${local.resource_prefix}-sql-${random_string.suffix.result}"

  database_version = "MYSQL_5_7"
  region           = local.region
  
  settings {
    tier = local.instance_tier
  }

  deletion_protection = false
}

resource "google_sql_database" "database" {
  name = "stratus-db"

  instance  = google_sql_database_instance.instance.name
  charset   = "utf8"
  collation = "utf8_general_ci"
}

resource "google_sql_user" "user" {
  name     = "root"
  instance = google_sql_database_instance.instance.name
  host     = "%"
  password = local.default_password
}

resource "google_storage_bucket" "bucket" {
  name = "${local.resource_prefix}-bucket-${random_string.suffix.result}"

  location      = local.region
  storage_class = "STANDARD"
  force_destroy = true
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "importer" {
  bucket  = google_storage_bucket.bucket.name 
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_sql_database_instance.instance.service_account_email_address}"
}

resource "google_storage_bucket_object" "sql_file" {
  name         = "init.sql"
  bucket       = google_storage_bucket.bucket.id 
  content      = base64decode("Q1JFQVRFIFRBQkxFIElGIE5PVCBFWElTVFMgdXNlcnMgKAogICAgYGlkYCBJTlQoMTApIE5PVCBOVUxMIEFVVE9fSU5DUkVNRU5ULAogICAgYHVzZXJuYW1lYCBWQVJDSEFSKDI1NSkgTk9UIE5VTEwsCiAgICBgcGFzc3dvcmRgIFZBUkNIQVIoMjU1KSBOT1QgTlVMTCwKICAgIFBSSU1BUlkgS0VZIGBpZGAgKGBpZGApCik7CklOU0VSVCBJTlRPIGB1c2Vyc2AoYHVzZXJuYW1lYCxgcGFzc3dvcmRgKSBWQUxVRVMoInNhdHJpYUB0aGlzY29tcGFueS5pZCIsTUQ1KCdQQHNzdzByZCcpKTsKSU5TRVJUIElOVE8gYHVzZXJzYChgdXNlcm5hbWVgLGBwYXNzd29yZGApIFZBTFVFUygiYWR5QHRoaXNjb21wYW55LmlkIixNRDUoJ1BAc3N3MHJkJykpOwpJTlNFUlQgSU5UTyBgdXNlcnNgKGB1c2VybmFtZWAsYHBhc3N3b3JkYCkgVkFMVUVTKCJwcmFkYW5hQHRoaXNjb21wYW55LmlkIixNRDUoJ1BAc3N3MHJkJykpOwo=")
  content_type = "text/plain"
}

data "httpclient_request" "req" {
  url             = "https://sqladmin.googleapis.com/v1/projects/${data.google_client_config.current.project}/instances/${google_sql_database_instance.instance.name}/import"
  request_method  = "POST"
  request_headers = {
    Content-Type: "application/json; charset=utf-8",
    Authorization: "Bearer ${data.google_client_config.current.access_token}",
  }
  request_body    = "{'importContext':{'fileType':'SQL','uri':'gs://${google_storage_bucket.bucket.id}/init.sql','database':'stratus-db'}}"

  depends_on = [google_storage_bucket_iam_member.importer]
}

output "bucket_name" {
  value = google_storage_bucket.bucket.name
}

output "sql_instance" {
  value = google_sql_database_instance.instance.name
}

output "display" {
  value = format("Cloud SQL '%s' ready (%s)", google_sql_database_instance.instance.name, data.httpclient_request.req.response_code)  
}
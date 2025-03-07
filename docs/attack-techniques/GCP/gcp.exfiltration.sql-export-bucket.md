---
title: Exporting Cloud SQL database to Storage bucket
---

# Exporting Cloud SQL database to Storage bucket

<span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 

<span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Exfiltrates data from a Cloud SQL database by exporting to internal storage bucket.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Cloud SQL instance
- Create a storage bucket and grant objectAdmin to Cloud SQL instance
- Populate the database

<span style="font-variant: small-caps;">Detonation</span>:

- Export the database into the storage bucket

!!! info

    Provisioning the Cloud SQL requires a few minutes.

<span style="font-variant: small-caps;">Reference:</span>

- https://cloud.google.com/sdk/gcloud/reference/sql/export/sql
- https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-sql-post-exploitation.html



## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.exfiltration.sql-export-bucket
```


## Detection

Exporting the database is detected as 'cloudsql.instances.export' in Cloud Logging.

Data Access logging for Cloud SQL instance is disabled by default, thus we need to enable it (if not enabled).

- Go to "IAM & Admin" -> "Audit Logs"
- Locate "Cloud SQL"
- on "Permission Types", check the "Admin read"

You can use following query to filter the events:

```
resource.type="cloudsql_database"
protoPayload.serviceName="cloudsql.googleapis.com"
protoPayload.methodName="cloudsql.instances.export"
```

Sample event (shortened for readability):

```json
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
    "methodName": "cloudsql.instances.export",
    "request": {
      @type: "type.googleapis.com/google.cloud.sql.v1.SqlInstancesExportRequest",
      "body": {
        "exportContext": {
          "databases": [
            "stratus-db"
          ],
          "fileType": "SQL",
          "uri": "gs://my-bucket-id/dump.sql.gz"
        }
      },
      "instance": "my-cloudsql-instance-id",
    }
    "resourceName": "projects/my-project-id/instances/my-cloudsql-instance-id",
    "serviceName": "cloudsql.googleapis.com",
  },
  "resource": {
    "type": "cloudsql_database"
  },
  "severity": "INFO"
}
```

subsequently, detect the 'storage.objects.create' event for creating the object on bucket.

```json
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
    "methodName": "storage.objects.create",
    "resourceName": "projects/_/buckets/my-bucket-id/objects/dump.sql.gz",
    "serviceName": "cloudsql.googleapis.com",
  },
  "resource": {
    "type": "gcs_bucket"
  },
  "severity": "INFO"
}
```
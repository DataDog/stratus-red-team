package gcp

import (
    "context"
    _ "embed"
    "fmt"
    "log"
    "time"
    "google.golang.org/api/sqladmin/v1"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
    const CodeBlock = "```"
    const AttackTechniqueId = "gcp.exfiltration.sql-export-bucket"

    stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
        ID:           AttackTechniqueId,
        FriendlyName: "Exporting Cloud SQL database to Storage bucket",
        Description: `
Exfiltrates data from a Cloud SQL database by exporting to internal storage bucket.

Warm-up:

- Create a Cloud SQL instance
- Create a storage bucket and grant objectAdmin to Cloud SQL instance
- Populate the database

Detonation:

- Export the database into the storage bucket

!!! info

    Provisioning the Cloud SQL requires a few minutes.

Reference:

- https://cloud.google.com/sdk/gcloud/reference/sql/export/sql
- https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-sql-post-exploitation.html
`,
        Detection: `
Exporting the database is detected as 'cloudsql.instances.export' in Cloud Logging.

Data Access logging for Cloud SQL instance is disabled by default, thus we need to enable it (if not enabled).

- Go to "IAM & Admin" -> "Audit Logs"
- Locate "Cloud SQL"
- on "Permission Types", check the "Admin read"

You can use following query to filter the events:

` + CodeBlock + `
resource.type="cloudsql_database"
protoPayload.serviceName="cloudsql.googleapis.com"
protoPayload.methodName="cloudsql.instances.export"
` + CodeBlock + `

Sample event (shortened for readability):

` + CodeBlock + `json
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
` + CodeBlock + `

subsequently, detect the 'storage.objects.create' event for creating the object on bucket.

` + CodeBlock + `json
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
` + CodeBlock + `
`,
        Platform:                   stratus.GCP,
        IsIdempotent:               true,
        MitreAttackTactics:         []mitreattack.Tactic{ mitreattack.Exfiltration },
        PrerequisitesTerraformCode: tf,
        Detonate:                   detonate,
    })
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
    gcp := providers.GCP()
    ctx := context.Background()

    projectId := gcp.GetProjectId()
    bucketName  := params["bucket_name"]
    sqlInstance := params["sql_instance"]

    // create service for API communication
    service, err := sqladmin.NewService(ctx, gcp.Options())
    if err != nil {
        return fmt.Errorf("Failed to create new service: %v", err)
    }

    // export the database
    req := &sqladmin.InstancesExportRequest {
        ExportContext: &sqladmin.ExportContext{
            Databases: []string{"stratus-db"},
            FileType:  "SQL",
            Uri:       fmt.Sprintf("gs://%s/dump.sql.gz", bucketName),
        },
    }

    if op, err := service.Instances.Export(projectId, sqlInstance, req).Do(); err != nil {
        return fmt.Errorf("Failed to export database: %v", err)
    }

    // wait for the export operation to complete
    for {
        op, err := service.Operations.Get(projectId, op.Name).Do()
        if err != nil {
            return fmt.Errorf("Failed to get operation status: %v", err)
        }

        if op.Status == "DONE" {
            if op.Error != nil {
                return fmt.Errorf("Export operation failed: %v", op.Error.Errors)
            }
            break
        }

        log.Println("Exporting in progress... waiting")
        time.Sleep(10 * time.Second)
    }
    
    log.Println("Database has been exported to the bucket")
    
    return nil
}
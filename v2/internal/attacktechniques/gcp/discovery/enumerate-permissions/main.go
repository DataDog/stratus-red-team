package gcp

import (
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"golang.org/x/oauth2/google"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

//go:embed main.tf
var tf []byte

const (
	testIAMChunkSize      = 100
	max429RetriesPerChunk = 6
	base429Backoff        = 1 * time.Minute
)

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.discovery.enumerate-permissions",
		FriendlyName: "Enumerate Permissions of a GCP Service Account",
		Description: `Enumerates permissions of a GCP service account by
calling <code>projects.testIamPermissions</code> on a large number of permissions.

This simulates an attacker who has compromised a service account key and is enumerating what the
service account has access to.

Warm-up:

- Create a GCP service account
- Grant a low-value permission set: Storage Object Viewer
- Create a service account key

Detonation:

- Call <code>projects.testIamPermissions</code>, with chunks of 100 permissions each time

References:

- https://securitylabs.datadoghq.com/articles/google-cloud-default-service-accounts/#enumerating-permissions-of-the-associated-service-account
- https://docs.cloud.google.com/iam/docs/reference/rest/v1/permissions/queryTestablePermissions
- https://cloud.google.com/resource-manager/reference/rest/v1/projects/testIamPermissions
- https://docs.cloud.google.com/iam/docs/roles-permissions
`,
		Detection: `Monitor repeated calls to <code>projects.testIamPermissions</code> from the same service account.

!!! warning

    These events are in
    <a href="https://cloud.google.com/logging/docs/audit#data-access">Data Access audit logs</a>,
    which are disabled by default.
    Enable Data Access logging for Resource Manager to capture this behavior.`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Discovery},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	saKeyBase64 := params["sa_key"]
	projectID := params["project_id"]
	saEmail := params["sa_email"]

	saKeyJSON, err := base64.StdEncoding.DecodeString(saKeyBase64)
	if err != nil {
		return fmt.Errorf("failed to decode service account key: %w", err)
	}

	ctx := context.Background()
	creds, err := google.CredentialsFromJSON(ctx, saKeyJSON, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return fmt.Errorf("failed to create credentials from service account key: %w", err)
	}

	testablePermissions := params["testable_permissions"]
	if testablePermissions == "" {
		return fmt.Errorf("testable permissions list is empty")
	}
	permissions := strings.Split(testablePermissions, ",")

	chunks := chunkPermissions(permissions, testIAMChunkSize)
	log.Printf("Enumerating permissions of %s on project %s (%d permissions, %d chunks of up to %d)",
		saEmail, projectID, len(permissions), len(chunks), testIAMChunkSize)

	crmService, err := cloudresourcemanager.NewService(
		ctx,
		option.WithTokenSource(creds.TokenSource),
		providers.GCP().Options(),
	)
	if err != nil {
		return fmt.Errorf("failed to create cloudresourcemanager service: %w", err)
	}

	startedAt := time.Now()
	testedPermissions := 0
	allowedPermissions := 0
	failedChunks := 0
	successfulChunks := 0
	allowedPermissionSet := make(map[string]struct{})
	allowedPermissionList := make([]string, 0, 256)

	for i, chunk := range chunks {
		resp, retriesUsed, err := callTestIAMPermissionsWith429Retry(ctx, crmService, projectID, chunk)
		progress := float64(i+1) / float64(len(chunks)) * 100
		if err != nil {
			failedChunks++
			log.Printf("  Progress: chunk %d/%d (%.1f%%) - failed (%v)",
				i+1, len(chunks), progress, err)
			continue
		}

		if retriesUsed > 0 {
			log.Printf("  Chunk %d/%d recovered after %d retries due to 429 rate limiting",
				i+1, len(chunks), retriesUsed)
		}

		successfulChunks++
		testedPermissions += len(chunk)
		for _, permission := range resp.Permissions {
			if _, exists := allowedPermissionSet[permission]; exists {
				continue
			}
			allowedPermissionSet[permission] = struct{}{}
			allowedPermissionList = append(allowedPermissionList, permission)
		}
		allowedPermissions = len(allowedPermissionList)
		log.Printf("  Progress: chunk %d/%d (%.1f%%) - tested %d permissions, allowed %d",
			i+1, len(chunks), progress, testedPermissions, allowedPermissions)
	}

	if successfulChunks == 0 {
		return fmt.Errorf("all %d testIamPermissions chunks failed", len(chunks))
	}

	log.Printf("Done: %d/%d chunks succeeded, %d failed, %d permissions tested, %d allowed, duration %s",
		successfulChunks, len(chunks), failedChunks, testedPermissions, allowedPermissions, time.Since(startedAt).Round(time.Second))
	log.Printf("Authorized actions found (%d):", allowedPermissions)
	for _, permission := range allowedPermissionList {
		log.Printf("  - %s", permission)
	}

	if failedChunks > 0 {
		log.Printf("Warning: %d chunks failed; results may be incomplete", failedChunks)
	}

	return nil
}

func chunkPermissions(permissions []string, chunkSize int) [][]string {
	// Split the permission list into fixed-size batches for testIamPermissions requests.
	if len(permissions) == 0 || chunkSize <= 0 {
		return nil
	}

	chunks := make([][]string, 0, (len(permissions)+chunkSize-1)/chunkSize)
	for start := 0; start < len(permissions); start += chunkSize {
		end := start + chunkSize
		if end > len(permissions) {
			end = len(permissions)
		}
		chunks = append(chunks, permissions[start:end])
	}

	return chunks
}

func isRateLimit(err error) bool {
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Code == http.StatusTooManyRequests
}

func callTestIAMPermissionsWith429Retry(
	ctx context.Context,
	service *cloudresourcemanager.Service,
	projectID string,
	permissions []string,
) (*cloudresourcemanager.TestIamPermissionsResponse, int, error) {
	backoff := base429Backoff
	for attempt := 0; attempt <= max429RetriesPerChunk; attempt++ {
		resp, err := service.Projects.TestIamPermissions(projectID, &cloudresourcemanager.TestIamPermissionsRequest{
			Permissions: permissions,
		}).Context(ctx).Do()
		if err == nil {
			return resp, attempt, nil
		}
		if !isRateLimit(err) || attempt == max429RetriesPerChunk {
			return nil, attempt, err
		}

		log.Printf("  Chunk hit 429 rate limit; retrying in %s (attempt %d/%d)",
			backoff.Round(time.Second), attempt+1, max429RetriesPerChunk)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, attempt, ctx.Err()
		}
		backoff *= 2
	}

	return nil, max429RetriesPerChunk, fmt.Errorf("unreachable retry state")
}

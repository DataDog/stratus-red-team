package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.exfiltration.open-port-22-ingress",
		FriendlyName: "Open Ingress Port 22 on a Firewall Rule",
		Description: `
Creates a GCP firewall rule that opens ingress TCP port 22 (SSH) to the world
(<code>0.0.0.0/0</code>) on a VPC network.

An attacker who has compromised a GCP environment may create such a rule to
establish SSH access to any VM instance in the affected network, or to exfiltrate
data by tunnelling traffic over SSH.

Warm-up:

- Create a VPC network

Detonation:

- Create a firewall rule named <code>&lt;vpc&gt;-allow-ssh</code> that allows TCP:22 ingress
  from <code>0.0.0.0/0</code>

Revert:

- Delete the firewall rule

References:

- https://cloud.google.com/vpc/docs/firewalls
- https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/insert
- https://unit42.paloaltonetworks.com/cloud-virtual-machine-attack-vectors/
- https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudVPC/unrestricted-ssh-access.html
`,
		Detection: `
Identify when a firewall rule opening a sensitive port to the world is created by
monitoring for <code>v1.compute.firewalls.insert</code> events in GCP Admin Activity
audit logs where <code>sourceRanges</code> includes <code>0.0.0.0/0</code> and
<code>allowed[].ports</code> contains port 22.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	vpcName := params["vpc_name"]
	ctx := context.Background()

	client, err := compute.NewFirewallsRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create firewalls client: %w", err)
	}
	defer client.Close()

	firewallName := vpcName + "-allow-ssh"
	log.Printf("Creating firewall rule %s allowing TCP:22 from 0.0.0.0/0 on VPC %s\n", firewallName, vpcName)
	op, err := client.Insert(ctx, &computepb.InsertFirewallRequest{
		Project: projectId,
		FirewallResource: &computepb.Firewall{
			Name:      ptr(firewallName),
			Network:   ptr(fmt.Sprintf("projects/%s/global/networks/%s", projectId, vpcName)),
			Direction: ptr("INGRESS"),
			Allowed: []*computepb.Allowed{
				{
					IPProtocol: ptr("tcp"),
					Ports:      []string{"22"},
				},
			},
			SourceRanges: []string{"0.0.0.0/0"},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create firewall rule: %w", err)
	}

	if err = op.Wait(ctx); err != nil {
		return fmt.Errorf("failed waiting for firewall rule creation: %w", err)
	}

	log.Printf("Successfully created firewall rule %s\n", firewallName)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	vpcName := params["vpc_name"]
	ctx := context.Background()

	client, err := compute.NewFirewallsRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create firewalls client: %w", err)
	}
	defer client.Close()

	firewallName := vpcName + "-allow-ssh"
	log.Printf("Deleting firewall rule %s\n", firewallName)
	op, err := client.Delete(ctx, &computepb.DeleteFirewallRequest{
		Project:  projectId,
		Firewall: firewallName,
	})
	if err != nil {
		return fmt.Errorf("failed to delete firewall rule: %w", err)
	}

	if err = op.Wait(ctx); err != nil {
		return fmt.Errorf("failed waiting for firewall rule deletion: %w", err)
	}

	log.Printf("Successfully deleted firewall rule %s\n", firewallName)
	return nil
}

func ptr[T any](v T) *T {
	return &v
}

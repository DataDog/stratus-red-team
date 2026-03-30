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
		ID:           "gcp.defense-evasion.remove-vpc-flow-logs",
		FriendlyName: "Disable VPC Flow Logs on a Subnet",
		Description: `
Disables VPC flow logging on a subnet by patching its log configuration.
VPC flow logs record network traffic metadata for all VM instances in a subnet,
providing visibility for network monitoring and forensic investigation.

Warm-up:

- Create a VPC network
- Create a subnet with VPC flow logs enabled

Detonation:

- Disable VPC flow logs on the subnet by patching its <code>logConfig.enable</code> field to <code>false</code>

Revert:

- Re-enable VPC flow logs on the subnet

References:

- https://cloud.google.com/vpc/docs/using-flow-logs
- https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks/patch
- https://github.com/GoogleCloudPlatform/security-analytics/blob/main/src/3.02/3.02.md
- https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/removing-vpc-flow-logs/
`,
		Detection: `
Identify when VPC flow logging is disabled on a subnet by monitoring for
<code>v1.compute.subnetworks.patch</code> events in GCP Admin Activity audit logs
where the request sets <code>logConfig.enable</code> to <code>false</code>.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.DefenseEvasion},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func setFlowLogsEnabled(providers stratus.CloudProviders, subnetName string, region string, enabled bool) error {
	gcp := providers.GCP()
	ctx := context.Background()
	projectId := gcp.GetProjectId()

	subnetsClient, err := compute.NewSubnetworksRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create subnetworks client: %w", err)
	}
	defer subnetsClient.Close()

	subnet, err := subnetsClient.Get(ctx, &computepb.GetSubnetworkRequest{
		Project:    projectId,
		Region:     region,
		Subnetwork: subnetName,
	})
	if err != nil {
		return fmt.Errorf("failed to get subnet %s: %w", subnetName, err)
	}

	op, err := subnetsClient.Patch(ctx, &computepb.PatchSubnetworkRequest{
		Project:    projectId,
		Region:     region,
		Subnetwork: subnetName,
		SubnetworkResource: &computepb.Subnetwork{
			Fingerprint: subnet.Fingerprint,
			LogConfig: &computepb.SubnetworkLogConfig{
				Enable: ptr(enabled),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to patch subnet %s: %w", subnetName, err)
	}

	if err = op.Wait(ctx); err != nil {
		return fmt.Errorf("failed waiting for subnet patch to complete: %w", err)
	}

	return nil
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	subnetName := params["subnet_name"]
	region := params["region"]

	log.Printf("Disabling VPC flow logs on subnet %s in region %s\n", subnetName, region)
	if err := setFlowLogsEnabled(providers, subnetName, region, false); err != nil {
		return err
	}
	log.Printf("Successfully disabled VPC flow logs on subnet %s\n", subnetName)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	subnetName := params["subnet_name"]
	region := params["region"]

	log.Printf("Re-enabling VPC flow logs on subnet %s in region %s\n", subnetName, region)
	if err := setFlowLogsEnabled(providers, subnetName, region, true); err != nil {
		return err
	}
	log.Printf("Successfully re-enabled VPC flow logs on subnet %s\n", subnetName)
	return nil
}

func ptr[T any](v T) *T {
	return &v
}

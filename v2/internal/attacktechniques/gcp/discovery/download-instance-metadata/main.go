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
	"google.golang.org/api/iterator"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.discovery.download-instance-metadata",
		FriendlyName: "Read GCE Instance Metadata via the Compute API",
		Description: `
Reads the metadata of a GCE instance via the Compute Engine API, simulating an attacker
who has obtained a service account token and uses it to enumerate running instances and
harvest secrets embedded in instance metadata fields such as <code>startup-script</code>.

Bootstrap scripts that install software, configure databases, or pull secrets from
environment variables are a common source of plaintext credentials in GCP environments.
Unlike the instance metadata server (169.254.169.254) which is only reachable from
within the VM, the Compute API can be queried remotely by any identity with the
<code>compute.instances.get</code> permission.

Warm-up:

- Create a GCE instance with a simulated <code>startup-script</code> metadata value
  containing embedded credentials

Detonation:

- Enumerate instances in the zone via the Compute API
- Fetch the full instance resource including all metadata fields
- Log the <code>startup-script</code> value if present

References:

- https://cloud.google.com/compute/docs/metadata/overview
- https://cloud.google.com/compute/docs/reference/rest/v1/instances/get
- https://cloud.google.com/blog/topics/threat-intelligence/cloud-metadata-abuse-unc2903/
- https://attack.mitre.org/techniques/T1552/005/
- https://securitylabs.datadoghq.com/articles/google-cloud-threat-detection/
`,
		Detection: `
Identify unexpected reads of instance metadata via the Compute API by monitoring for
<code>compute.instances.get</code> and <code>compute.instances.list</code> events in GCP
Data Access audit logs originating from identities that do not normally perform Compute
Engine management operations.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Discovery},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	instanceName := params["instance_name"]
	zone := params["zone"]
	ctx := context.Background()

	instancesClient, err := compute.NewInstancesRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create Compute instances client: %w", err)
	}
	defer instancesClient.Close()

	// Enumerate all instances in the zone to simulate broad discovery before
	// narrowing down to the target.
	log.Printf("Listing GCE instances in project %s zone %s\n", projectId, zone)
	listIt := instancesClient.List(ctx, &computepb.ListInstancesRequest{
		Project: projectId,
		Zone:    zone,
	})
	var instanceCount int
	for {
		inst, err := listIt.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to list instances in zone %s: %w", zone, err)
		}
		instanceCount++
		log.Printf("  Found instance: %s (status: %s)\n", inst.GetName(), inst.GetStatus())
	}
	log.Printf("Discovered %d instance(s) in zone %s\n", instanceCount, zone)

	// Fetch the full instance resource to read all metadata fields.
	log.Printf("Fetching full metadata for instance %s\n", instanceName)
	instance, err := instancesClient.Get(ctx, &computepb.GetInstanceRequest{
		Project:  projectId,
		Zone:     zone,
		Instance: instanceName,
	})
	if err != nil {
		return fmt.Errorf("failed to get instance %s: %w", instanceName, err)
	}

	if instance.Metadata == nil || len(instance.Metadata.Items) == 0 {
		log.Printf("Instance %s has no metadata items\n", instanceName)
		return nil
	}

	for _, item := range instance.Metadata.Items {
		key := item.GetKey()
		value := item.GetValue()
		log.Printf("  Metadata key: %s\n", key)
		if key == "startup-script" {
			log.Printf("  startup-script contents (may contain credentials):\n%s\n", value)
		}
	}

	return nil
}

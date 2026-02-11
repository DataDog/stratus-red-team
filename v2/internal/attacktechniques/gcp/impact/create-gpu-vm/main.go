package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const defaultZone = "us-central1-a"
const acceleratorType = "nvidia-tesla-t4"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.impact.create-gpu-vm",
		FriendlyName: "Create a GCE GPU Virtual Machine",
		Description: `
Creates a GCE virtual machine instance with GPU accelerators, simulating an attacker creating GPU instances for cryptomining.

Warm-up:

- None

Detonation:

- Attempt to create a GCE instance with a GPU accelerator (` + acceleratorType + `) attached

Note: The instance creation may fail in GCP projects without GPU quota. However, the GCP audit log is still generated
with the GPU accelerator request parameters, which is sufficient for detection rules to match on.

<span style="font-weight: bold;">⚠️ Warning:</span> If the instance is successfully created, it will incur GPU costs. Make sure to revert the technique after detonation to clean up created resources and avoid unnecessary costs.

References:

- https://www.mandiant.com/resources/blog/detecting-cryptomining-cloud
- https://cloud.google.com/blog/topics/threat-intelligence/detecting-cryptomining-using-vpc-flow-logs
`,
		Detection: `
Identify when GCE instances with GPU accelerators are created by monitoring for <code>v1.compute.instances.insert</code> or
<code>beta.compute.instances.insert</code> events in GCP Admin Activity audit logs where the request includes <code>guestAccelerators</code>.

Attackers frequently provision GPU-enabled VMs for cryptocurrency mining after compromising cloud credentials.
GPU VMs are significantly more expensive than standard VMs and are rarely used in most environments.

Detection criteria:

<ul>
  <li>Monitor <code>compute.instances.insert</code> events where the request contains <code>guestAccelerators.acceleratorCount</code></li>
  <li>Alert on any instance creation with GPU accelerators, especially from unusual principals or outside of normal change windows</li>
  <li>Consider higher severity when the caller IP is associated with known anonymizing proxies or botnets</li>
</ul>
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	ctx := context.Background()
	projectId := gcp.GetProjectId()
	suffix := params["suffix"]

	instancesClient, err := compute.NewInstancesRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create compute client: %w", err)
	}
	defer instancesClient.Close()

	instanceName := fmt.Sprintf("stratus-red-team-gpu-%s", suffix)
	machineType := fmt.Sprintf("zones/%s/machineTypes/n1-standard-4", defaultZone)
	acceleratorType := fmt.Sprintf("zones/%s/acceleratorTypes/%s", defaultZone, acceleratorType)

	log.Printf("Creating GPU-enabled instance %s in zone %s\n", instanceName, defaultZone)

	_, err = instancesClient.Insert(ctx, &computepb.InsertInstanceRequest{
		Project: projectId,
		Zone:    defaultZone,
		InstanceResource: &computepb.Instance{
			Name:        &instanceName,
			MachineType: &machineType,
			Disks: []*computepb.AttachedDisk{{
				AutoDelete: ptr(true),
				Boot:       ptr(true),
				InitializeParams: &computepb.AttachedDiskInitializeParams{
					SourceImage: ptr("projects/debian-cloud/global/images/family/debian-12"),
					DiskSizeGb:  ptr(int64(10)),
				},
			}},
			NetworkInterfaces: []*computepb.NetworkInterface{{
				Network: ptr("global/networks/default"),
			}},
			GuestAccelerators: []*computepb.AcceleratorConfig{{
				AcceleratorType:  ptr(acceleratorType),
				AcceleratorCount: ptr(int32(1)),
			}},
			Scheduling: &computepb.Scheduling{
				OnHostMaintenance: ptr("TERMINATE"),
			},
		},
	})

	if err != nil {
		if strings.Contains(err.Error(), "quota") || strings.Contains(err.Error(), "QUOTA") || strings.Contains(err.Error(), "Quota") {
			log.Println("Note: Instance creation failed due to GPU quota restrictions, but the GCP audit log was still generated and is sufficient to trigger detection rules")
			return nil
		}
		return fmt.Errorf("instance creation failed: %w", err)
	}

	log.Printf("Successfully created GPU-enabled instance %s\n", instanceName)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	ctx := context.Background()
	projectId := gcp.GetProjectId()
	suffix := params["suffix"]
	instanceName := fmt.Sprintf("stratus-red-team-gpu-%s", suffix)

	instancesClient, err := compute.NewInstancesRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create compute client: %w", err)
	}
	defer instancesClient.Close()

	log.Printf("Deleting GPU instance %s in zone %s\n", instanceName, defaultZone)

	op, err := instancesClient.Delete(ctx, &computepb.DeleteInstanceRequest{
		Project:  projectId,
		Zone:     defaultZone,
		Instance: instanceName,
	})
	if err != nil {
		if strings.Contains(err.Error(), "notFound") {
			log.Println("Instance not found (likely was never created due to quota), nothing to clean up")
			return nil
		}
		return fmt.Errorf("failed to delete GPU instance: %w", err)
	}

	if err = op.Wait(ctx); err != nil {
		return fmt.Errorf("failed waiting for GPU instance deletion to complete: %w", err)
	}

	log.Println("Successfully deleted GPU instance")
	return nil
}

func ptr[T any](v T) *T {
	return &v
}

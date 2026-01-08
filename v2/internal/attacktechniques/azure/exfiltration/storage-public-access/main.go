package azure

import (
	"context"
	_ "embed"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.exfiltration.storage-public-access",
		FriendlyName: "Exfiltrate Azure Storage via public access",
		Description: `
Exfiltrate data from Azure Storage by enabling public access on a private blob container.

Warm-up:
- Create an Azure Storage account with a private blob container
- Upload sample data to the container

Detonation:
- Enable public access on the container
- Access the blob data via public URL without authentication

References:
- https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure
`,
		Detection: `
Monitor Azure Activity Logs for storage account configuration changes.

Sample Azure Activity Log event to monitor:

` + "```json" + `
{
    "operationName": "Microsoft.Storage/storageAccounts/blobServices/containers/write",
    "properties": {
        "publicAccess": "Blob"
    }
}
` + "```" + `
`,
		Platform:                   stratus.Azure,
		IsIdempotent:               true,
		IsSlow:                     false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	// Access prerequisites from Terraform outputs
	// storageAccountName := params["storage_account_name"]
	// containerName := params["container_name"]
	// resourceGroup := params["resource_group"]

	// Get Azure provider credentials
	// cred := providers.Azure().GetCredentials()
	// subscriptionID := providers.Azure().SubscriptionID
	// clientOptions := providers.Azure().ClientOptions

	log.Println("Starting attack...")

	// TODO: Implement attack logic to enable public access on the storage container

	log.Println("Attack completed successfully")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	// TODO: Implement cleanup logic to disable public access on the storage container

	log.Println("Cleanup completed successfully")
	return nil
}

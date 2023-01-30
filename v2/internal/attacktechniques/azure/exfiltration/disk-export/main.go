package azure

import (
	"context"
	_ "embed"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"time"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.exfiltration.disk-export",
		FriendlyName: "Export Disk Through SAS URL",
		Description: `
Generate a public [Shared Access Signature (SAS)](https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview) URL to download an Azure disk.

Warm-up:

- Create an Azure-managed disk

Detonation:

- Generated a Shared Access Signature (SAS) URL for the disk

References:

- https://powerzure.readthedocs.io/en/latest/Functions/operational.html#get-azurevmdisk
- https://zigmax.net/azure-disk-data-exfiltration/
`,
		Detection: `
Identify <code>Microsoft.Compute/disks/beginGetAccess/action</code> events in Azure Activity logs.

Sample event (redacted for clarity):

` + codeBlock + `json hl_lines="6"
{
  "resourceId": "/SUBSCRIPTIONS/<your-subscription-id>/RESOURCEGROUPS/RG-IKFFQ01Z/PROVIDERS/MICROSOFT.COMPUTE/DISKS/STRATUS-RED-TEAM-DISK",
  "evt": {
    "category": "Administrative",
    "outcome": "Success",
    "name": "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION"
  },
  "level": "Information",
  "properties": {
    "hierarchy": "ecc2b97b-844b-414e-8123-b925dddf87ed/2fd72d85-b49f-4e19-b567-4a8cb7301e8b",
    "message": "Microsoft.Compute/disks/beginGetAccess/action",
    "eventCategory": "Administrative",
    "entity": "/subscriptions/<your-subscription-id/resourceGroups/rg-ikffq01z/providers/Microsoft.Compute/disks/stratus-red-team-disk"
  }
}
` + codeBlock + `
`,
		Platform:                   stratus.Azure,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	diskName := params["disk_name"]
	disksClient, err := getAzureDisksClient()
	if err != nil {
		return errors.New("unable to instantiate Azure disks client: " + err.Error())
	}

	log.Println("Creating Shared Access Secret (SAS) URL for disk " + diskName)

	readPermissions := armcompute.GrantAccessData{
		Access:            to.Ptr(armcompute.AccessLevelRead),
		DurationInSeconds: ptr.Int32(3600),
	}
	sharingTask, err := disksClient.BeginGrantAccess(context.Background(), params["resource_group_name"], diskName, readPermissions, nil)
	if err != nil {
		return errors.New("unable to export disk: " + err.Error())
	}

	sharingResult, err := sharingTask.PollUntilDone(context.Background(), &runtime.PollUntilDoneOptions{Frequency: 1 * time.Second})
	if err != nil {
		return errors.New("disk export failed: " + err.Error())
	}

	exportUrl := *sharingResult.AccessSAS
	log.Println("Successfully generated SAS URL for disk at " + exportUrl)
	return nil
}

func revert(params map[string]string) error {
	diskName := params["disk_name"]
	disksClient, err := getAzureDisksClient()
	if err != nil {
		return errors.New("unable to instantiate Azure disks client: " + err.Error())
	}

	log.Println("Revoking Shared Access Secret (SAS) URL for disk " + diskName)

	revokeTask, err := disksClient.BeginRevokeAccess(context.Background(), params["resource_group_name"], diskName, nil)
	if err != nil {
		return errors.New("unable to revoke access to disk: " + err.Error())
	}

	_, err = revokeTask.PollUntilDone(context.Background(), &runtime.PollUntilDoneOptions{Frequency: 1 * time.Second})
	if err != nil {
		return errors.New("revokation of disk access failed: " + err.Error())
	}

	log.Println("Successfully revoked SAS URL for disk " + diskName)
	return nil
}

func getAzureDisksClient() (*armcompute.DisksClient, error) {
	cred := providers.Azure().GetCredentials()
	subscriptionID := providers.Azure().SubscriptionID
	clientOptions := providers.Azure().ClientOptions
	return armcompute.NewDisksClient(subscriptionID, cred, clientOptions)
}

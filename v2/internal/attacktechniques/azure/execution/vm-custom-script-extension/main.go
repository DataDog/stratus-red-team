package azure

import (
	"context"
	_ "embed"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.execution.vm-custom-script-extension",
		FriendlyName: "Execute Command on Virtual Machine using Custom Script Extension",
		Description: `
By utilizing the 'CustomScriptExtension' extension on a Virtual Machine, an attacker can pass PowerShell commands to the VM as SYSTEM.

References:

- https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows
- https://microsoft.github.io/Azure-Threat-Research-Matrix/Execution/AZT301/AZT301-2/

Warm-up: 

- Create a virtual machine

Detonation: 

- Configure a custom script extension for the virtual machine
`,
		Detection: `
Identify Azure events of type <code>Microsoft.Compute/virtualMachines/extensions/write</code>. Sample below (redacted for clarity).

` + codeBlock + `json hl_lines="7"
{
  "duration": 0,
  "resourceId": "/SUBSCRIPTIONS/<your-subscription-id>/RESOURCEGROUPS/RG-HAT6H48Q/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/VM-HAT6H48Q/EXTENSIONS/CUSTOMSCRIPTEXTENSION-STRATUS-EXAMPLE",
  "evt": {
    "category": "Administrative",
    "outcome": "Start",
    "name": "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE"
  },
  "resource_name": "customscriptextension-stratus-example",
  "time": "2022-06-18T19:57:27.8617215Z",
  "properties": {
    "hierarchy": "ecc2b97b-844b-414e-8123-b925dddf87ed/<your-subscription-id>",
    "message": "Microsoft.Compute/virtualMachines/extensions/write",
    "eventCategory": "Administrative",
    "entity": "/subscriptions/<your-subscription-id>/resourceGroups/rg-hat6h48q/providers/Microsoft.Compute/virtualMachines/vm-hat6h48q/extensions/CustomScriptExtension-Stratus-Example"
  },
}
` + codeBlock + `
`,
		Platform:                   stratus.Azure,
		IsSlow:                     true,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

const ExtensionName = "CustomScriptExtension-StratusRedTeam-Example"

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	vmName := params["vm_name"]
	resourceGroup := params["resource_group_name"]

	ctx := context.Background()
	cred := providers.Azure().GetCredentials()
	subscriptionID := providers.Azure().SubscriptionID
	clientOptions := providers.Azure().ClientOptions

	client, err := armcompute.NewVirtualMachineExtensionsClient(subscriptionID, cred, clientOptions)
	if err != nil {
		return errors.New("failed to create VM extensions client: " + err.Error())
	}

	log.Println("Configuring Custom Script Extension for VM instance " + vmName)
	log.Println("This will cause a command to be run as SYSTEM on the machine")

	vmExtension := armcompute.VirtualMachineExtension{
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
	}

	poller, err := client.BeginCreateOrUpdate(ctx,
		resourceGroup,
		vmName,
		ExtensionName,
		vmExtension,
		nil)

	if err != nil {
		return errors.New("unable to create virtual machine extension: " + err.Error())
	}

	ctxWithTimeout, done := context.WithTimeout(context.Background(), 60*3*time.Second)
	defer done()
	_, err = poller.PollUntilDone(ctxWithTimeout, &runtime.PollUntilDoneOptions{Frequency: 2 * time.Second})
	if err != nil {
		return errors.New("unable to retrieve the output of the command ran on the virtual machine: " + err.Error())
	}
	log.Println("Extension created, the command was executed as SYSTEM")

	// TODO enhancement: figure out how to retrieve the output of the executed commabd to ensure it was executed

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
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

	log.Println("Reverting Custom Script Extension for VM instance " + vmName)

	poller, err := client.BeginDelete(ctx,
		resourceGroup,
		vmName,
		ExtensionName,
		&armcompute.VirtualMachineExtensionsClientBeginDeleteOptions{ResumeToken: ""})

	if err != nil {
		return errors.New("unable to remove custom script extension: " + err.Error())
	}

	ctxWithTimeout, done := context.WithTimeout(context.Background(), 60*3*time.Second)
	defer done()

	_, err = poller.PollUntilDone(ctxWithTimeout, &runtime.PollUntilDoneOptions{Frequency: 2 * time.Second})
	if err != nil {
		return errors.New("unable to remove custom script extension: " + err.Error())
	}

	return nil
}

package azure

import (
	"context"
	_ "embed"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
	"time"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.execution.vm-run-command",
		FriendlyName: "Execute Commands on Virtual Machine using Run Command",
		Description: `
By utilizing the 'RunCommand' feature on a Virtual Machine, an attacker can pass:

- Windows: PowerShell commands to the VM as SYSTEM.
- Linux: Shell commands to the VM as root.

References:

- https://docs.microsoft.com/en-us/azure/virtual-machines/windows/run-command
- https://docs.microsoft.com/en-us/azure/virtual-machines/linux/run-command
- https://github.com/hausec/Azure-Attack-Matrix/blob/main/Execution/AZT201/AZT201-1.md

Warm-up: 

- Create a virtual machine

Detonation: 

- Invoke a RunCommand on the target virtual machine
`,
		Detection: `
Identify <code>Microsoft.Compute/virtualMachines/runCommand/action</code> 
and <code>Microsoft.Compute/virtualMachines/runCommands/write</code> events in Azure Activity logs.

Sample event (redacted for clarity):

` + codeBlock + `json hl_lines="7"
{
    "caller": "you@domain.tld",
	"eventTimestamp": "2022-06-01T11:39:35.6986539Z",
    "id": "/subscriptions/<your-subscription-id>/resourceGroups/rg-4x3tj2hb/providers/Microsoft.Compute/virtualMachines/vm-4x3tj2hb/events/25235036-3b0c-46e7-97d0-5bea476a6ab8/ticks/637896803756986539",
    "level": "Informational",
    "operationName": {
        "value": "Microsoft.Compute/virtualMachines/runCommand/action",
        "localizedValue": "Run Command on Virtual Machine"
    },
    "resourceGroupName": "rg-4x3tj2hb",
    "resourceProviderName": {
        "value": "Microsoft.Compute",
        "localizedValue": "Microsoft.Compute"
    },
    "resourceType": {
        "value": "Microsoft.Compute/virtualMachines",
        "localizedValue": "Microsoft.Compute/virtualMachines"
    },
    "resourceId": "/subscriptions/<your-subscription-id>/resourceGroups/rg-4x3tj2hb/providers/Microsoft.Compute/virtualMachines/vm-4x3tj2hb",
    "status": {
        "value": "Succeeded",
        "localizedValue": "Succeeded"
    },
    "properties": {
        "eventCategory": "Administrative",
        "entity": "/subscriptions/<your-subscription-id>/resourceGroups/rg-4x3tj2hb/providers/Microsoft.Compute/virtualMachines/vm-4x3tj2hb",
        "message": "Microsoft.Compute/virtualMachines/runCommand/action",
        "hierarchy": "<your-tenant-id>/<your-subscription-id>"
    },
    "relatedEvents": []
}
` + codeBlock + `
`,
		Platform:                   stratus.Azure,
		IsSlow:                     true,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	vmObjectId := params["vm_instance_object_id"]
	vmName := params["vm_name"]
	resourceGroup := params["resource_group_name"]

	cred := providers.Azure().GetCredentials()
	subscriptionID := providers.Azure().SubscriptionID
	clientOptions := providers.Azure().ClientOptions

	log.Println("Issuing Run Command for VM instance " + vmObjectId)
	vmClient, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, clientOptions)
	runCommandInput := armcompute.RunCommandInput{
		CommandID: to.Ptr("RunPowerShellScript"),
		Script:    []*string{to.Ptr("Get-Service")},
	}
	if err != nil {
		return errors.New("unable to instantiate Azure virtual machine client: " + err.Error())
	}

	commandCreation, err := vmClient.BeginRunCommand(context.Background(), resourceGroup, vmName, runCommandInput, nil)
	if err != nil {
		return errors.New("unable to run a command on the virtual machine: " + err.Error())
	}

	log.Println("Waiting for command to be run on the VM")
	ctxWithTimeout, done := context.WithTimeout(context.Background(), 60*3*time.Second) // This can sometimes be quite slow
	defer done()
	commandResult, err := commandCreation.PollUntilDone(ctxWithTimeout, &runtime.PollUntilDoneOptions{Frequency: 2 * time.Second})
	if err != nil {
		return errors.New("unable to retrieve the output of the command ran on the virtual machine: " + err.Error())
	}

	_ = *commandResult.RunCommandResult.Value[0].Message // contains the output of the command executed
	log.Println("Command successfully executed on the virtual machine")
	return nil
}

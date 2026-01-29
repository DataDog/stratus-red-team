package azure

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.impact.resource-lock",
		FriendlyName: "Delete Azure resource lock",
		Description: `
NOTE: Due to resource lock delays, the warmup and cleanup steps of this technique can take several minutes.

Disable Azure resource locks to allow resource deletion. Resource locks can be applied to any Azure resource, resource group, or subscription. This technique uses a lock on a resource group containing an Azure storage account as an example.

References:

- https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
- https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources

Warm-up: 

- Create a storage account
- Set storage account as ReadOnly using an Azure resource lock at the resource group level

Detonation: 

- Delete Azure resource lock

`,
		Detection: `
Monitor Azure Activity Logs for resource lock changes, specifically <code>Microsoft.Authorization/locks/delete</code> operations. Once an attacker has removed a resource lock, they are able to modify and delete resources that were protected by that lock.

Sample Azure Activity Log event to monitor:

` + codeBlock + `json hl_lines="1 5"
    "operationName": {
        "value": "Microsoft.Authorization/locks/delete",
        "localizedValue": "Delete management locks"
    },
	"properties": {
        "properties": {
        "eventCategory": "Administrative",
        "entity": "/subscriptions/[SUBSCRIPTION-ID]/resourceGroups/stratus-red-team-lock-storage-71mu/providers/Microsoft.Authorization/locks/stratus-storage-lock-71mu",
        "message": "Microsoft.Authorization/locks/delete",
        "hierarchy": "[REMOVED]"
    }
`,
		Platform:                   stratus.Azure,
		IsIdempotent:               true,
		IsSlow:                     true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}


func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()

	log.Println("Starting technique execution")

	storageAccount := params["storage_account_name"]
	lock := params["resource_lock"]
	resourceGroup := params["resource_group"]

	locksClient, err := armlocks.NewManagementLocksClient(providers.Azure().SubscriptionID, providers.Azure().GetCredentials(), providers.Azure().ClientOptions)
	if err != nil {
	    return fmt.Errorf("unable to create management locks client: %w", err)
	}

	// Delete the resource lock
	log.Println("Deleting resource lock on resource group " + resourceGroup + " impacting storage account " + storageAccount)
	_, err = locksClient.DeleteAtResourceGroupLevel(ctx, resourceGroup, lock, nil)
	if err != nil {
	    return fmt.Errorf("unable to delete resource lock: %w", err)
	}
	log.Println("Successfully deleted resource lock")

	log.Println("Technique execution completed")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()

	log.Println("Starting cleanup")

	storageAccount := params["storage_account_name"]
	resourceGroup := params["resource_group"]
	lock := params["resource_lock"]

	locksClient, err := armlocks.NewManagementLocksClient(providers.Azure().SubscriptionID, providers.Azure().GetCredentials(), providers.Azure().ClientOptions)
	if err != nil {
		return fmt.Errorf("unable to create management locks client: %w", err)
	}

	// Re-create the resource lock at ReadOnly level on the resource group
	log.Println("Re-creating resource lock on resource group "  + resourceGroup + " impacting storage account " + storageAccount)
	_, err = locksClient.CreateOrUpdateAtResourceGroupLevel(ctx, resourceGroup, lock,
		armlocks.ManagementLockObject{
			Properties: &armlocks.ManagementLockProperties{
				Level: to.Ptr(armlocks.LockLevelReadOnly),
				Notes: to.Ptr("Stratus Resource lock"),
			},
		},
		nil,
	)
	if err != nil {
		return fmt.Errorf("unable to re-create resource lock: %w", err)
	}
	log.Println("Successfully re-created resource lock")

	log.Println("Cleanup completed")
	return nil
}

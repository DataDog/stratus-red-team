package aws

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"strings"
	"time"
)

//go:embed main.tf
var tf []byte

const commandToExecute = `echo "id=$(id), hostname=$(hostname)"`

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.execution.ssm-send-command",
		FriendlyName: "Usage of ssm:SendCommand on multiple instances",
		IsSlow:       true,
		Description: `
Simulates an attacker utilizing AWS Systems Manager (SSM) to execute commands through SendCommand on multiple EC2 instances.

Warm-up:

- Create multiple EC2 instances and a VPC (takes a few minutes).

Detonation: 

- Runs <code>ssm:SendCommand</code> on several EC2 instances, to execute the command <code>` + commandToExecute + `</code> on each of them.

References:

- https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/#send-command
- https://www.chrisfarris.com/post/aws-ir/
- https://www.invictus-ir.com/news/aws-cloudtrail-cheat-sheet
- https://securitycafe.ro/2023/01/17/aws-post-explitation-with-ssm-sendcommand/
`,
		Detection: `
Identify, through CloudTrail's <code>SendCommand</code> event, especially when <code>requestParameters.instanceIds</code> contains several instances. Sample event:

` + codeBlock + `json
{
  "eventSource": "ssm.amazonaws.com",
  "eventName": "SendCommand",
  "requestParameters": {
    "instanceIds": [
      "i-0f364762ca43f9661",
      "i-0a86d1f61db2b9b5d",
      "i-08a69bfbe21c67e70"
    ],
    "documentName": "AWS-RunShellScript",
    "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
    "interactive": false
  }
}
` + codeBlock + `

While this technique uses a single call to <code>ssm:SendCommand</code> on several instances, an attacker may use one call per instance to execute commands on. In that case, the <code>SendCommand</code> event will be emitted for each call.
`,
		Platform:                   stratus.AWS,
		PrerequisitesTerraformCode: tf,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution},
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ssmClient := ssm.NewFromConfig(providers.AWS().GetConnection())
	instanceIDs := getInstanceIds(params)

	if err := utils.WaitForInstancesToRegisterInSSM(ssmClient, instanceIDs); err != nil {
		return fmt.Errorf("failed to wait for instances to register in SSM: %v", err)
	}

	log.Println("Instances are ready and registered in SSM!")
	log.Println("Executing command '" + commandToExecute + "' through ssm:SendCommand on all instances...")

	result, err := ssmClient.SendCommand(context.Background(), &ssm.SendCommandInput{
		InstanceIds:  instanceIDs,
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters: map[string][]string{
			"commands": {commandToExecute},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send command to instances: %v", err)
	}

	commandId := result.Command.CommandId
	log.Println("Command sent successfully. Command ID: " + *commandId)
	log.Println("Waiting for command outputs")

	for _, instanceID := range instanceIDs {
		result, err := ssm.NewCommandExecutedWaiter(ssmClient).WaitForOutput(context.Background(), &ssm.GetCommandInvocationInput{
			InstanceId: &instanceID,
			CommandId:  commandId,
		}, 2*time.Minute)
		if err != nil {
			return fmt.Errorf("failed to execute command on instance %s: %v", instanceID, err)
		}
		log.Print(fmt.Sprintf("Successfully executed on instance %s. Output: %s", instanceID, *result.StandardOutputContent))
	}

	return nil
}

func getInstanceIds(params map[string]string) []string {
	instanceIds := strings.Split(params["instance_ids"], ",")
	// iterate over instanceIds and remove \n, \r, spaces and " from each instanceId
	for i, instanceId := range instanceIds {
		instanceIds[i] = strings.Trim(instanceId, " \"\n\r")
	}
	return instanceIds
}

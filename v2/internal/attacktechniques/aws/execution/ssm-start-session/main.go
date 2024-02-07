package aws

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.execution.ssm-start-session",
		FriendlyName: "Usage of ssm:StartSession on multiple instances",
		IsSlow:       true,
		Description: `
Simulates an attacker utilizing AWS Systems Manager (SSM) StartSession to gain unauthorized interactive access to multiple EC2 instances.

Warm-up:

- Create multiple EC2 instances and a VPC (takes a few minutes).

Detonation: 

- Initiates a connection to the EC2 for a Session Manager session.

References:

- https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/#session-manager
- https://awstip.com/responding-to-an-attack-in-aws-9048a1a551ac
`,
		Detection: `
Identify, through CloudTrail's <code>StartSession</code> event, when a user is starting an interactive session to multiple EC2 instances. Sample event:

` + codeBlock + `
{
  "eventSource": "ssm.amazonaws.com",
  "eventName": "StartSession",
  "requestParameters": {
    "target": "i-123456"
  },
  "responseElements": {
        "sessionId": "...",
        "tokenValue": "Value hidden due to security reasons.",
        "streamUrl": "wss://ssmmessages.eu-west-1.amazonaws.com/v1/data-channel/..."
   },
}
` + codeBlock + `
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
	instanceIDs := strings.Split(params["instance_ids"], ",")

	for _, instanceID := range instanceIDs {
		cleanInstanceID := strings.Trim(instanceID, " \"\n\r")
		_, err := ssmClient.StartSession(context.TODO(), &ssm.StartSessionInput{
			Target: &cleanInstanceID,
		})

		if err != nil {
			return fmt.Errorf("failed to start session with instance %s: %v", cleanInstanceID, err)
		}

		fmt.Printf("Session started with instance %s\n", cleanInstanceID)
	}

	return nil
}

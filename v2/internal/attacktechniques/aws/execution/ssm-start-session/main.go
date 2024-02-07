package aws

import (
	"context"
	_ "embed"
	"fmt"
	"time"
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

- https://awstip.com/responding-to-an-attack-in-aws-9048a1a551ac (evidence of usage in the wild)
- https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/#session-manager
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
	const maxRetries = 5 // Maximum number of retries
	const retryDelay = 10 * time.Second // Delay between retries

	for _, instanceID := range instanceIDs {
		success := false
		cleanInstanceID := strings.Trim(instanceID, " \"\n\r")

		for attempt := 0; attempt < maxRetries; attempt++ {
			session, err := ssmClient.StartSession(context.Background(), &ssm.StartSessionInput{
				Target: &cleanInstanceID,
			})
			if err != nil {
				fmt.Printf("Attempt %d: StartSession failed for instance %s, retrying in %v...\n", attempt+1, cleanInstanceID, retryDelay)
				time.Sleep(retryDelay)
				continue
			}

			fmt.Printf("Session started with instance %s\n", cleanInstanceID)
			success = true

			// Attempt to terminate the session to not leave it hanging
			_, err = ssmClient.TerminateSession(context.Background(), &ssm.TerminateSessionInput{
				SessionId: session.SessionId,
			})
			if err != nil {
				return fmt.Errorf("failed to terminate SSM session with instance %s: %v", cleanInstanceID, err)
			}
			break
		}

		if !success {
			return fmt.Errorf("failed to start session with instance %s after %d retries", cleanInstanceID, maxRetries)
		}
	}
	return nil
}

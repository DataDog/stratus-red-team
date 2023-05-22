package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"strconv"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.credential-access.ec2-get-password-data",
		FriendlyName: "Retrieve EC2 Password Data",
		Description: `
Runs ec2:GetPasswordData from a role that does not have permission to do so. This simulates an attacker attempting to
retrieve RDP passwords on a high number of Windows EC2 instances.

See https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetPasswordData.html

Warm-up: 

- Create an IAM role without permissions to run ec2:GetPasswordData

Detonation: 

- Assume the role 
- Run a number of ec2:GetPasswordData calls (which will be denied) using fictitious instance IDs
`,
		Detection:                  "Identify principals making a large number of ec2:GetPasswordData calls, using CloudTrail's GetPasswordData event",
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.CredentialAccess},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

const numCalls = 30

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	roleArn := params["role_arn"]

	awsConnection := providers.AWS().GetConnection()
	if err := utils.WaitForAndAssumeAWSRole(&awsConnection, roleArn); err != nil {
		return err
	}
	ec2Client := ec2.NewFromConfig(awsConnection)

	log.Println("Running ec2:GetPasswordData on " + strconv.Itoa(numCalls) + " random instance IDs")
	for i := 0; i < numCalls; i++ {
		// Generate a fake, real-looking instance ID
		// Since we don't have the permission, we don't care if the instance actually exists
		instanceId := "i-" + utils.RandomString(16)

		_, err := ec2Client.GetPasswordData(context.Background(), &ec2.GetPasswordDataInput{
			InstanceId: &instanceId,
		})

		if err == nil {
			return errors.New("ec2:GetPasswordData should have returned an error (access denied)")
		}
	}

	return nil
}

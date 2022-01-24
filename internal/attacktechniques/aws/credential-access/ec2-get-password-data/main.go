package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/datadog/stratus-red-team/internal/utils"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
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
- Run a number of ec2:GetPasswordData calls (which will be denied) using fictious instance IDs
`,
		Platform:                   stratus.AWS,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.CredentialAccess},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

const numCalls = 30

func detonate(params map[string]string) error {
	roleArn := params["role_arn"]

	cfg, _ := config.LoadDefaultConfig(context.Background())
	stsClient := sts.NewFromConfig(cfg)
	cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, roleArn))
	ec2Client := ec2.NewFromConfig(cfg)

	log.Println("Running ec2:GetPasswordData on " + strconv.Itoa(numCalls) + " random instance IDs")

	for i := 0; i < numCalls; i++ {
		// Generate a fake, real-looking instance ID
		// Since we don't have the permission, we don't care if the instance actually exists
		instanceId := "i-" + utils.RandomString(16)

		_, err := ec2Client.GetPasswordData(context.Background(), &ec2.GetPasswordDataInput{
			InstanceId: aws.String(instanceId),
		})

		if err == nil {
			return errors.New("ec2:GetPasswordData should have returned an error (access denied)")
		}
	}

	return nil
}

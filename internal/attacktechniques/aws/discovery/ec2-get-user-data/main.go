package aws

import (
	"context"
	_ "embed"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/datadog/stratus-red-team/internal/utils"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.discovery.ec2-download-user-data",
		FriendlyName: "Download EC2 Instance User Data",
		Description: `
Runs ec2:DescribeInstanceAttribute on several instances. This simulates an attacker attempting to
retrieve Instance User Data that may include installation scripts and hard-coded secrets for deployment.

See: 

- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- https://hackingthe.cloud/aws/general-knowledge/introduction_user_data/
- https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/ec2__download_userdata/main.py

Warm-up: 

- Create an IAM role without permissions to run ec2:DescribeInstanceAttribute

Detonation: 

- Run ec2:DescribeInstanceAttribute on multiple fictitious instance IDs
- These calls will result in access denied errors
`,
		/* Detection: `

		Through CloudTrail's <code>DescribeInstanceAttribute</code> event.

		See:
		* [Associated Sigma rule](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_ec2_download_userdata.yml)`, */
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Discovery},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

const numCalls = 15

func detonate(params map[string]string) error {
	roleArn := params["role_arn"]

	cfg, _ := config.LoadDefaultConfig(context.Background())
	stsClient := sts.NewFromConfig(cfg)
	cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, roleArn))
	ec2Client := ec2.NewFromConfig(cfg)

	for i := 0; i < numCalls; i++ {
		// Generate a fake, real-looking instance ID
		instanceId := "i-" + utils.RandomHexString(8)

		// Call DescribeInstanceAttribute to retrieve the userData attribute
		// Expected Client.UnauthorizedOperation
		ec2Client.DescribeInstanceAttribute(context.Background(), &ec2.DescribeInstanceAttributeInput{
			Attribute:  types.InstanceAttributeNameUserData,
			InstanceId: &instanceId,
		})

		log.Println("Running ec2:DescribeInstanceAttribute to retrieve userData on " + instanceId)
	}

	return nil
}

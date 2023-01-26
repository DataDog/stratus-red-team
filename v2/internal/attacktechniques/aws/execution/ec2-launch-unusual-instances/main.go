package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"strings"
)

//go:embed main.tf
var tf []byte

const instanceType = types.InstanceTypeP2Xlarge
const numInstances = 10

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.execution.ec2-launch-unusual-instances",
		FriendlyName: "Launch Unusual EC2 instances",
		Description: `
Attempts to launch several unusual EC2 instances (` + string(instanceType) + `).

Warm-up: Creates an IAM role that doesn't have permissions to launch EC2 instances. 
This ensures the attempts is not successful, and the attack technique is fast to detonate.

Detonation: Attempts to launch several unusual EC2 instances. The calls will fail as the IAM role does not have sufficient permissions.
`,
		Detection: `
Trough CloudTrail events with the event name <code>RunInstances</code> and error
<code>Client.UnauthorizedOperation</code>. The <code>eventSource</code> will be
<code>ec2.amazonaws.com</code> and the <code>requestParameters.instanceType</code>
field will contain the instance type that was attempted to be launched.

Depending on your account limits you might also see <code>VcpuLimitExceeded</code> error codes.
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	awsConnection := providers.AWS().GetConnection()

	amiId := params["ami_id"]
	roleArn := params["role_arn"]
	subnetId := params["subnet_id"]

	stsClient := sts.NewFromConfig(awsConnection)
	awsConnection.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, roleArn))
	ec2Client := ec2.NewFromConfig(awsConnection)

	log.Printf("Attempting to run up to %d instances of type %s\n", numInstances, string(instanceType))
	_, err := ec2Client.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId:  aws.String(amiId),
		SubnetId: aws.String(subnetId),
		// Note: These parameters will attempt to launch the maximum between 1 and `numInstances` instances
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(numInstances),
		InstanceType: instanceType,
	})

	if err == nil {
		// We expected an error
		return errors.New("expected ec2:RunInstances to return an error")
	}

	if !strings.Contains(err.Error(), "AccessDenied") {
		// We expected an *AccessDenied* error
		return errors.New("expected ec2:RunInstances to return an access denied error, got instead: " + err.Error())
	}

	log.Println("Got an access denied error as expected")

	return nil
}

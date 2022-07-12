package aws

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/aws/smithy-go/ptr"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
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
<code>ec2.amazonaws.com</code> and the <code>requestParameters.instanceType<code>
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

func detonate(params map[string]string) error {
	ctx := context.Background()
	awsConnection := providers.AWS().GetConnection()

	// get ami image id before assuming role with limited access
	amiId, err := getAmazonLinuxAmiId(&ctx, &awsConnection)
	if err != nil {
		return fmt.Errorf("could not get a valid EC2 AMI id: %v", err)
	}

	stsClient := sts.NewFromConfig(awsConnection)
	awsConnection.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, params["role_arn"]))
	ec2Client := ec2.NewFromConfig(awsConnection)

	_, err = ec2Client.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId:      &amiId,
		MinCount:     ptr.Int32(numInstances),
		MaxCount:     ptr.Int32(numInstances),
		InstanceType: instanceType, // types.InstanceTypeP4d24xlarge,
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

// getAmazonLinuxAmiId returns the most current Amazon Linux AMI image id (as AMIs are region specific)
func getAmazonLinuxAmiId(ctx *context.Context, config *aws.Config) (string, error) {
	ec2Client := ec2.NewFromConfig(*config)

	filterName, filterArch, filterRootDev := "name", "architecture", "root-device-type"
	input := ec2.DescribeImagesInput{
		Filters: []types.Filter{
			{
				Name:   &filterName,
				Values: []string{"amzn2-ami-kernel-*"},
			},
			{
				Name:   &filterArch,
				Values: []string{"x86_64"},
			},
			{
				Name:   &filterRootDev,
				Values: []string{"ebs"},
			},
			{
				Name:   &filterRootDev,
				Values: []string{"ebs"},
			},
		},
	}
	output, err := ec2Client.DescribeImages(*ctx, &input)
	if err != nil {
		return "", fmt.Errorf("could not get ec2 images list from aws: %v", err)
	}

	images := output.Images
	sort.Slice(images, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339, *images[i].CreationDate)
		tj, _ := time.Parse(time.RFC3339, *images[j].CreationDate)
		return ti.After(tj)
	})

	if len(images) == 0 {
		return "", fmt.Errorf("error determining latest ec2 image to use, image list is empty")
	}

	return *images[0].ImageId, nil
}

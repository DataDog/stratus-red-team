package aws

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.discovery.ec2-spin-up-unusual-instances",
		FriendlyName: "Attempt to spin up several unusual EC2 instances",
		Description: `Tries to spin up several unusual EC2 instances

Warm-up:

- Creates an IAM role that, doesn't have permissions to create and run new EC2 instances
- This ensures the attempts are not successful, and the attack technique is fast to detonate

Detonation:

- Try to spin up spin up several unusual EC2 instances
- The calls will fail as the IAM role does not have sufficient permissions
`,
		Detection: `Trough CloudTrail events with the event name <code>RunInstances</code> and error
<code>Client.UnauthorizedOperation</code>. The <code>eventSource</code> will be
<code>ec2.amazonaws.com</code> itself. Further, the <code>requestParameters.instanceType<code>
field will contain the instance type that was attempted to be launched.
Depending on your account limits you might also see <code>VcpuLimitExceeded</code> error codes.
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Discovery},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	},
	)
}

func detonate(params map[string]string) error {
	ctx := context.Background()

	awsConnection := providers.AWS().GetConnection()

	// get ami image id before assuming role with limited access
	amiID, err := getALAmiID(&ctx, &awsConnection)
	if err != nil {
		return fmt.Errorf("could not get a valid ec2 ami id: %v", err)
	}

	stsClient := sts.NewFromConfig(awsConnection)
	awsConnection.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, params["role_arn"]))
	ec2Client := ec2.NewFromConfig(awsConnection)

	minCount := int32(1)
	maxCount := int32(10)
	_, err = ec2Client.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId:      &amiID,
		MinCount:     &minCount,
		MaxCount:     &maxCount,
		InstanceType: types.InstanceTypeP2Xlarge, // types.InstanceTypeP4d24xlarge,
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			if ae.ErrorCode() != "UnauthorizedOperation" && ae.ErrorCode() != "VcpuLimitExceeded" {
				return fmt.Errorf("error trying to run ec2 instance: %v", err)
			}
			log.Printf("Received expected error '%s'", ae.ErrorCode())
		}
	}

	return nil
}

// revert does not require any specific actions for this technique
func revert(_ map[string]string) error {
	log.Println("Reverted successfully (nothing to do)")
	return nil
}

// getALAmiID returns the most current Amazon Linux AMI image id (as AMIs are region specific)
func getALAmiID(ctx *context.Context, config *aws.Config) (string, error) {
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
		return "", fmt.Errorf("error determining latest ec2 image to use, image list is zero")
	}

	return *images[0].ImageId, nil
}

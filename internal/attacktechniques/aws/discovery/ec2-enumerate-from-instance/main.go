package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
	"strings"
	"time"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.discovery.ec2-enumerate-from-instance",
		FriendlyName: "Execute Discovery Commands on an EC2 Instance",
		IsSlow:       true,
		Description: `
Runs several discovery commands on an EC2 instance:

- sts:GetCallerIdentity
- s3:ListBuckets
- iam:GetAccountSummary
- iam:ListRoles
- iam:ListUsers
- iam:GetAccountAuthorizationDetails
- ec2:DescribeSnapshots
- cloudtrail:DescribeTrails
- guardduty:ListDetectors

The commands will be run under the identity of the EC2 instance role, simulating an attacker having compromised an EC2 instance and running discovery commands on it.

Warm-up:

- Create the prerequisite EC2 instance and VPC (takes a few minutes).

Detonation: 

- Run the discovery commands, over SSM. The commands will be run under the identity of the EC2 instance role.
`,
		Detection: `
Identify when an EC2 instance performs unusual enumeration calls.

An action can be determined to have been performed by an EC2 instance under its instance role when the attribute
<code>userIdentity.arn</code> of a CloudTrail event ends with <code>i-*</code>, for instance:

<code>
arn:aws:sts::012345678901:assumed-role/my-instance-role/i-0adc17a5acb70d9ae
</code>
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Discovery},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	ssmClient := ssm.NewFromConfig(providers.AWS().GetConnection())
	instanceId := params["instance_id"]
	commands := []string{
		"aws sts get-caller-identity || true", // Note: we need the || true to ensure the command exits with status 0, even if the instance role doesn't have the permission
		"aws s3 ls || true",
		"aws iam get-account-summary || true",
		"aws iam list-roles || true",
		"aws iam list-users || true",
		"aws iam get-account-authorization-details >/dev/null || true", // Piping to /dev/null as it contains a lot of output
		"aws ec2 describe-snapshots || true",
		"aws cloudtrail describe-trails || true",
		"aws guardduty list-detectors || true",
	}

	log.Println("Running commands through SSM on " + instanceId + ":\n  - " + strings.Join(commands, "\n  - "))

	result, err := ssmClient.SendCommand(context.Background(), &ssm.SendCommandInput{
		DocumentName: aws.String("AWS-RunShellScript"),
		InstanceIds:  []string{instanceId},
		Parameters: map[string][]string{
			"commands": commands,
		},
	})
	if err != nil {
		return errors.New("unable to send SSM command to instance: " + err.Error())
	}
	_, err = ssm.NewCommandExecutedWaiter(ssmClient).WaitForOutput(context.Background(), &ssm.GetCommandInvocationInput{
		CommandId:  result.Command.CommandId,
		InstanceId: &instanceId,
	}, 2*time.Minute)

	if err != nil {
		return errors.New("unable to execute SSM commands on instance: " + err.Error())
	}

	return nil
}

package aws

import (
	"context"
	_ "embed"
	"log"

	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"

	"github.com/aws/aws-sdk-go-v2/service/ses"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.discovery.ses-enumerate",
		FriendlyName: "Enumeration of SES service",
		Description: `
Runs the following discovery commands on SES to enumerate email sending limits and identities, typically used for reconnaissance purposes before launching a phishing campaign:

	- ses:GetSendQuota
	- ses:ListIdentities

See:

- https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me
- https://docs.aws.amazon.com/ses/latest/APIReference/API_GetSendQuota.html
- https://docs.aws.amazon.com/ses/latest/APIReference/API_ListIdentities.html

Warm-up: 

- Create an IAM role with the AmazonSESReadOnlyAccess policy attached. The role can be assumed by any user in the AWS account of the caller.

Detonation: 

- Run ses:GetSendQuota API call
- Run ses:ListIdentities API call
`,
		Detection: `
Through CloudTrail's <code>GetSendQuota</code> and <code>ListIdentities</code> events.
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Discovery},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	roleArn := params["role_arn"]
	awsConnection := providers.AWS().GetConnection()
	if err := utils.WaitForAndAssumeAWSRole(&awsConnection, roleArn); err != nil {
		return err
	}
	sesClient := ses.NewFromConfig(awsConnection)
	var maxItems int32 = 10
	listIdentitiesInput := ses.ListIdentitiesInput{
		MaxItems:  &maxItems,
		NextToken: nil,
	}

	identies, err := sesClient.ListIdentities(context.Background(), &listIdentitiesInput)
	if err != nil {
		return err
	}

	log.Println("ListIdentities output: ", identies.Identities)

	quotas, err := sesClient.GetSendQuota(context.Background(), &ses.GetSendQuotaInput{})
	if err != nil {
		return err
	}

	log.Printf("GetSendQuota output, max24hoursend: %d, maxsendrate: %d, sentlast24hours: %d\n",
		int(quotas.Max24HourSend), int(quotas.MaxSendRate), int(quotas.SentLast24Hours))

	return nil
}

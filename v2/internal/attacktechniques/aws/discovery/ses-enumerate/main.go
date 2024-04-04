package aws

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"strings"

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
		FriendlyName: "Enumerate SES",
		Description: `
Simulates an attacker enumerating SES. Attackers frequently use this enumeration technique after having compromised an access key, to use it to launch phishing campaigns or further resell stolen credentials.

Warm-up: 

- Create an IAM role with the <code>AmazonSESReadOnlyAccess</code> policy attached. The role can be assumed by any user in the AWS account of the caller.

Detonation: 

- Assume the created IAM role
- Perform <code>ses:GetSendQuota</code> to discover the current [email sending quotas](https://docs.aws.amazon.com/ses/latest/APIReference/API_GetSendQuota.html).
- Perform <code>ses:ListIdentities</code> to discover the list of [verified identities](https://docs.aws.amazon.com/ses/latest/APIReference/API_ListIdentities.html) in the account.

References:
- https://securitylabs.datadoghq.com/articles/following-attackers-trail-in-aws-methodology-findings-in-the-wild/#most-common-enumeration-techniques
- https://www.invictus-ir.com/news/ransomware-in-the-cloud
- https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/#post-125981-_kdq0vw6banab
- https://permiso.io/blog/s/aws-ses-pionage-detecting-ses-abuse/
- https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me
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

	log.Println("Enumerating verified SES identities using ses:ListIdentities")
	identities, err := sesClient.ListIdentities(context.Background(), &ses.ListIdentitiesInput{})
	if err != nil {
		return fmt.Errorf("unable to list SES identities: %w", err)
	}

	if len(identities.Identities) == 0 {
		log.Println("No verified SES identities found")
	} else {
		log.Printf("Found %d verified SES identities:", len(identities.Identities))
		log.Println("\n- " + strings.Join(identities.Identities, "\n- "))
	}

	log.Println("Enumerating SES quotas")
	quotas, err := sesClient.GetSendQuota(context.Background(), &ses.GetSendQuotaInput{})
	if err != nil {
		return fmt.Errorf("unable to get SES quotas: %w", err)
	}

	log.Printf("Current quotas: max24hoursend: %d, maxsendrate: %d, sentlast24hours: %d\n", int(quotas.Max24HourSend), int(quotas.MaxSendRate), int(quotas.SentLast24Hours))

	return nil
}

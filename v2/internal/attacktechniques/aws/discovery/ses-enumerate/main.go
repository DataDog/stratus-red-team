package aws

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/ses"
)

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.discovery.ses-enumerate",
		FriendlyName: "Enumerate SES",
		Description: `
Simulates an attacker enumerating SES. Attackers frequently use this enumeration technique after having compromised an access key, to use it to launch phishing campaigns or further resell stolen credentials.

Warm-up: None.

Detonation: 
TODO
- Perform <code>ses:GetSendQuota</code> to discover the current [email sending quotas](https://docs.aws.amazon.com/ses/latest/APIReference/API_GetSendQuota.html).
- Perform <code>ses:ListIdentities</code> to discover the list of [identities](https://docs.aws.amazon.com/ses/latest/APIReference/API_ListIdentities.html) in the account.
- When identities are found, use <code>ses:GetIdentityVerificationAttributes</code> to discover the [verification status](https://docs.aws.amazon.com/ses/latest/APIReference/API_GetIdentityVerificationAttributes.html) of each identity.

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
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Discovery},
		Detonate:           detonate,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	awsConnection := providers.AWS().GetConnection()
	sesClient := ses.NewFromConfig(awsConnection)
	sesV2Client := sesv2.NewFromConfig(awsConnection)

	/*log.Println("Checking is SES e-mail sending is enabled in the current region")
	result, err := sesClient.GetAccountSendingEnabled(context.Background(), &ses.GetAccountSendingEnabledInput{})
	if err != nil {
		return fmt.Errorf("unable to check if SES sending is enabled: %w", err)
	}
	if result.Enabled {
		log.Println("SES e-mail sending is enabled")
	} else {
		log.Println("SES e-mail sending is disabled")
	}*/

	log.Println("Checking if SES e-mail sending is enabled in the current region, and quotas in place")
	account, err := sesV2Client.GetAccount(context.Background(), &sesv2.GetAccountInput{})
	if err != nil {
		return fmt.Errorf("unable to get SES account details: %w", err)
	}
	if account.SendingEnabled {
		log.Println("SES e-mail sending is enabled in the current region")
	} else {
		log.Println("SES e-mail sending is disabled in the current region")
	}
	if account.ProductionAccessEnabled {
		log.Println("SES is in production mode!")
	} else {
		log.Println("SES is in sandbox mode")
	}
	log.Printf("SES quotas: max24hoursend: %d, maxsendrate: %d, sentlast24hours: %d\n", int(account.SendQuota.Max24HourSend), int(account.SendQuota.MaxSendRate), int(account.SendQuota.SentLast24Hours))

	log.Println("Enumerating verified SES identities using ses:ListIdentities")
	identities, err := sesClient.ListIdentities(context.Background(), &ses.ListIdentitiesInput{})
	if err != nil {
		return fmt.Errorf("unable to list SES identities: %w", err)
	}

	if len(identities.Identities) == 0 {
		log.Println("No verified SES identities found")
	} else {
		log.Printf("Found %d verified SES identities", len(identities.Identities))
		verificationAttributes, err := sesClient.GetIdentityVerificationAttributes(context.Background(), &ses.GetIdentityVerificationAttributesInput{
			Identities: identities.Identities,
		})
		if err != nil {
			return fmt.Errorf("unable to get identity verification attributes: %w", err)
		}
		for identity := range verificationAttributes.VerificationAttributes {
			log.Printf("- Identity %s has verification status '%s'", identity, verificationAttributes.VerificationAttributes[identity].VerificationStatus)
		}
	}

	/*log.Println("Enumerating SES quotas")
	quotas, err := sesClient.GetSendQuota(context.Background(), &ses.GetSendQuotaInput{})
	if err != nil {
		return fmt.Errorf("unable to get SES quotas: %w", err)
	}

	log.Printf("Current quotas: max24hoursend: %d, maxsendrate: %d, sentlast24hours: %d\n", int(quotas.Max24HourSend), int(quotas.MaxSendRate), int(quotas.SentLast24Hours))*/

	return nil
}

package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.privilege-escalation.iam-update-user-login-profile",
		FriendlyName: "Change IAM user password",
		Description: `
Establishes persistence by updating a Login Profile on an existing IAM user to change its password. This allows an attacker to hijack 
an IAM user with an existing login profile.

Warm-up:

- Create an IAM user with a login profile

Detonation: 

- Update the user's login profile to change its password

References:

- https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me
- https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/
- https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
`,
		Detection: `
Through CloudTrail's <code>UpdateLoginProfile</code> events.
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
	userName := params["user_name"]
	newPassword := utils.RandomString(16) + ".#1Aa" // extra characters to ensure we meet password requirements, no matter the password policy

	log.Println("Changing console password for IAM user " + userName)
	_, err := iamClient.UpdateLoginProfile(context.Background(), &iam.UpdateLoginProfileInput{
		UserName: &userName,
		Password: &newPassword,
	})
	if err != nil {
		return errors.New("unable to update IAM login profile: " + err.Error())
	}

	accountId, _ := utils.GetCurrentAccountId(providers.AWS().GetConnection())
	log.Println("Updated console password for user")
	loginUrl := "https://" + accountId + ".signin.aws.amazon.com/console"
	log.Println("You can log in at: " + loginUrl)
	log.Println("User name: " + userName)
	log.Println("Password: " + newPassword)

	return nil
}

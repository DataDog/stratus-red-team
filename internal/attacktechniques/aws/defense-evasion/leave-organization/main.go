package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.defense-evasion.leave-organization",
		FriendlyName:       "Attempt to Leave the AWS Organization",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Attempts to leave the AWS Organization (unsuccessfully - will hit an AccessDenied error). 
Security configurations are often defined at the organization level (GuardDuty, SecurityHub, CloudTrail...). 
Leaving the organization can disrupt or totally shut down these controls.


Warm-up: 

- Create an IAM role without permissions to run organizations:LeaveOrganization

Detonation: 

- Call organization:LeaveOrganization to simulate an attempt to leave the AWS Organization.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	roleArn := params["role_arn"]

	cfg, _ := config.LoadDefaultConfig(context.Background())
	stsClient := sts.NewFromConfig(cfg)
	cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, roleArn))
	organizationsClient := organizations.NewFromConfig(cfg)

	log.Println("Attempting to leave the AWS organization (will trigger an Access Denied error)")

	_, err := organizationsClient.LeaveOrganization(context.Background(), &organizations.LeaveOrganizationInput{})

	if err == nil {
		// We expected an error
		return errors.New("expected organizations:LeaveOrganization to return an error")
	}

	if !strings.Contains(err.Error(), "AccessDenied") {
		// We expected an *AccessDenied* error
		return errors.New("expected organizations:LeaveOrganization to return an access denied error, got instead: " + err.Error())
	}

	log.Println("Got an access denied error as expected")
	return nil
}

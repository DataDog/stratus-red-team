package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.defense-evasion.organizations-leave",
		FriendlyName:       "Attempt to Leave the AWS Organization",
		Platform:           stratus.AWS,
		IsIdempotent:       true,
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
		Detection: `
Any attempts from a child account to leave its AWS Organization should be considered suspicious. 

Use the CloudTrail event <code>LeaveOrganization</code>.`,
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
	organizationsClient := organizations.NewFromConfig(awsConnection)

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

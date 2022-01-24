package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
	"strconv"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.credential-access.retrieve-all-ssm-parameters",
		FriendlyName: "Retrieve And Decrypt SSM Parameters",
		Description: `
Retrieves and decrypts a high number (30) of SSM Parameters available in an AWS region.

Warm-up: 

- Create multiple SSM Parameters

Detonation: 

- Use ssm:DescribeParameters to list SSM Parameters in the current region
- Use ssm:GetParameters by batch of 10 (maximal supported value) to retrieve the values of the SSM Parameters
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.CredentialAccess},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(map[string]string) error {
	cfg, _ := config.LoadDefaultConfig(context.Background())
	ssmClient := ssm.NewFromConfig(cfg)

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
		var names = []string{}
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

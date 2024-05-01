package aws

import (
	"context"
	_ "embed"
	"errors"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.defense-evasion.dns-delete-logs",
		FriendlyName:       "Delete DNS query logs",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Deletes a Route53 DNS Resolver query logging configuration. Simulates an attacker disrupting DNS logging.

Warm-up:

- Create a DNS logging configuration.

Detonation:

- Delete the DNS logging configuration using <code>route53:DeleteResolverQueryLogConfig</code>.`,
		Detection: `
Identify when a DNS logging configuration is deleted, through CloudTrail's <code>DeleteResolverQueryLogConfig</code> event.
`,
		IsIdempotent:               false, // can't delete a DNS logging configuration twice
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	resolverClient := route53resolver.NewFromConfig(providers.AWS().GetConnection())
	queryLoggingConfigId := params["route53_logger_id"]

	log.Println("Deleting DNS logging configuration " + queryLoggingConfigId)

	_, err := resolverClient.DeleteResolverQueryLogConfig(context.Background(), &route53resolver.DeleteResolverQueryLogConfigInput{
		ResolverQueryLogConfigId: &queryLoggingConfigId,
	})

	if err != nil {
		return errors.New("unable to delete DNS logging configuration: " + err.Error())
	}

	return nil
}

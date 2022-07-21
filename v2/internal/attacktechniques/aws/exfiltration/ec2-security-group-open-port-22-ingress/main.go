package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.exfiltration.ec2-security-group-open-port-22-ingress",
		FriendlyName:       "Open Ingress Port 22 on a Security Group",
		Platform:           stratus.AWS,
		IsIdempotent:       false, // cannot call ec2:AuthorizeSecurityGroupIngress multiple times with the same parameters
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		Description: `
Opens ingress traffic on port 22 from the Internet (0.0.0.0/0).

Warm-up: 

- Create a VPC and a security group inside it.

Detonation: 

- Call ec2:AuthorizeSecurityGroupIngress to allow ingress traffic on port 22 from 0.0.0.0/0.
`,
		Detection: `
You can use the CloudTrail event <code>AuthorizeSecurityGroupIngress</code> when:

- <code>requestParameters.cidrIp</code> is <code>0.0.0.0/0</code> (or an unknown external IP)
- and <code>requestParameters.fromPort</code>/<code>requestParameters.toPort</code> is not a commonly exposed port or corresponds to a known administrative protocol such as SSH or RDP
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())

	// Find the snapshot to exfiltrate
	securityGroupId := params["security_group_id"]

	// Open port 22 to the world
	log.Println("Opening port 22 from the Internet on " + securityGroupId)

	_, err := ec2Client.AuthorizeSecurityGroupIngress(context.Background(), &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:    &securityGroupId,
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

func revert(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())

	// Find the snapshot to exfiltrate
	securityGroupId := params["security_group_id"]

	// Open port 22 to the world
	log.Println("Closing port 22 from the Internet on " + securityGroupId)

	_, err := ec2Client.RevokeSecurityGroupIngress(context.Background(), &ec2.RevokeSecurityGroupIngressInput{
		GroupId:    &securityGroupId,
		CidrIp:     aws.String("0.0.0.0/0"),
		FromPort:   aws.Int32(22),
		ToPort:     aws.Int32(22),
		IpProtocol: aws.String("tcp"),
	})

	if err != nil {
		return errors.New("unable to close port 22 on security group " + err.Error())
	}

	return nil
}

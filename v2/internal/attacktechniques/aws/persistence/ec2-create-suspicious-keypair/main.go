package aws

import (
	"context"
	"errors"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

const EnvVarKeyPairName = "STRATUS_RED_TEAM_KEYPAIR"
const defaultKeyPairName = "stratus-red-team-keypair"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.ec2-create-suspicious-keypair",
		FriendlyName: "Create an EC2 Key Pair with a Suspicious Name",
		Platform:     stratus.AWS,
		IsIdempotent: false, // cannot call ec2:CreateKeyPair twice with the same key name
		MitreAttackTactics: []mitreattack.Tactic{
			mitreattack.Persistence,
		},
		FrameworkMappings: []stratus.FrameworkMappings{
			{
				Framework: stratus.ThreatTechniqueCatalogAWS,
				Techniques: []stratus.TechniqueMapping{
					{
						Name: "Account Manipulation: Additional Cloud Credentials",
						ID:   "T1098.001",
						URL:  "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.001.html",
					},
				},
			},
		},
		Description: `
Creates an EC2 key pair, simulating attackers planting their own key pair so they can later
launch or access EC2 instances without relying on the credentials they used to gain initial access.

By default, the key pair is named <code>` + defaultKeyPairName + `</code>. To simulate a known suspicious
name observed being reused across unrelated compromised AWS environments (such as <code>xg1</code>),
set the <code>` + EnvVarKeyPairName + `</code> environment variable to the desired key pair name.

Warm-up: None.

Detonation:

- Call ec2:DescribeInstances filtered by the key name, to check whether the environment has
  been compromised before and the key pair is already in use.
- Call ec2:CreateKeyPair to create a new key pair.

References:

- https://securitylabs.datadoghq.com/articles/following-attackers-trail-in-aws-methodology-findings-in-the-wild/#atomic-indicator-ec2-keypair-creation
`,
		Detection: `
Identify calls to the CloudTrail event <code>CreateKeyPair</code>, optionally preceded shortly before
by a <code>DescribeInstances</code> call whose <code>requestParameters.filterSet</code> filters on
<code>key-name</code>.

Known suspicious key names observed reused across unrelated compromised environments include
<code>xg1</code> and <code>temp_key_pair</code> — matching <code>requestParameters.keyName</code>
against a list of such known-bad values is a high-confidence atomic indicator.
`,
		Detonate: detonate,
		Revert:   revert,
	})
}

func getKeyPairName() string {
	if name := os.Getenv(EnvVarKeyPairName); name != "" {
		return name
	}
	return defaultKeyPairName
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	keyPairName := getKeyPairName()

	log.Println("Checking for existing usage of key pair " + keyPairName)
	_, err := ec2Client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("key-name"),
				Values: []string{keyPairName},
			},
		},
	})
	if err != nil {
		return errors.New("unable to describe instances: " + err.Error())
	}

	log.Println("Creating EC2 key pair " + keyPairName)
	_, err = ec2Client.CreateKeyPair(context.Background(), &ec2.CreateKeyPairInput{
		KeyName: aws.String(keyPairName),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeKeyPair,
				Tags: []types.Tag{
					{Key: aws.String("StratusRedTeam"), Value: aws.String("true")},
				},
			},
		},
	})
	if err != nil {
		return errors.New("unable to create key pair: " + err.Error())
	}

	return nil
}

func revert(_ map[string]string, providers stratus.CloudProviders) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	keyPairName := getKeyPairName()

	log.Println("Deleting EC2 key pair " + keyPairName)
	_, err := ec2Client.DeleteKeyPair(context.Background(), &ec2.DeleteKeyPairInput{
		KeyName: aws.String(keyPairName),
	})
	if err != nil {
		return errors.New("unable to delete key pair: " + err.Error())
	}

	return nil
}

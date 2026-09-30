package aws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

const EnvVarKeyPairName = "STRATUS_RED_TEAM_KEY_PAIR"
const defaultKeyPairNamePrefix = "key-stratus-red-team-"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.ec2-create-suspicious-keypair",
		FriendlyName: "Create an EC2 Key Pair with a Suspicious Name",
		Platform:     stratus.AWS,
		IsIdempotent: true, // default name is randomized per call; overriding it is the caller's responsibility
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

By default, the key pair is named <code>` + defaultKeyPairNamePrefix + `<random suffix></code>, which
matches a "key*" naming convention associated with attacker-planted key pairs while still being
unique per detonation. To simulate a specific known suspicious name observed being reused across
unrelated compromised AWS environments (such as <code>xg1</code>), set the <code>` + EnvVarKeyPairName + `</code>
environment variable to the desired key pair name.

Warm-up: None.

Detonation:

- Call ec2:DescribeInstances filtered by the key name, to check whether the key pair is
  already in use.
- Call ec2:CreateKeyPair to create a new key pair.

References:

- https://securitylabs.datadoghq.com/articles/following-attackers-trail-in-aws-methodology-findings-in-the-wild/#atomic-indicator-ec2-keypair-creation
`,
		Detection: `
Identify calls to the CloudTrail event <code>CreateKeyPair</code> where <code>requestParameters.keyName</code>
starts with <code>key</code> and the caller authenticated with an IAM user access key
(<code>userIdentity.accessKeyId</code> starting with <code>AKIA</code>) — a known suspicious
naming convention for attacker-planted key pairs, as opposed to a descriptive, project-scoped name.
`,
		Detonate: detonate,
		Revert:   revert,
	})
}

func getKeyPairName() string {
	if name := os.Getenv(EnvVarKeyPairName); name != "" {
		return name
	}
	return defaultKeyPairNamePrefix + randomSuffix()
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

// revert deletes by the exact override name when STRATUS_RED_TEAM_KEY_PAIR is set (stable
// across the detonate/revert calls), or falls back to the StratusRedTeam tag otherwise, since
// the default name is randomized per detonation and Go code cannot persist state between the
// detonate and revert calls (they run in separate processes).
func revert(_ map[string]string, providers stratus.CloudProviders) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())

	if overrideName := os.Getenv(EnvVarKeyPairName); overrideName != "" {
		log.Println("Deleting EC2 key pair " + overrideName)
		_, err := ec2Client.DeleteKeyPair(context.Background(), &ec2.DeleteKeyPairInput{
			KeyName: aws.String(overrideName),
		})
		if err != nil {
			return errors.New("unable to delete key pair: " + err.Error())
		}
		return nil
	}

	result, err := ec2Client.DescribeKeyPairs(context.Background(), &ec2.DescribeKeyPairsInput{
		Filters: []types.Filter{
			{Name: aws.String("tag:StratusRedTeam"), Values: []string{"true"}},
		},
	})
	if err != nil {
		return errors.New("unable to list key pairs: " + err.Error())
	}

	for _, keyPair := range result.KeyPairs {
		log.Println("Deleting EC2 key pair " + *keyPair.KeyName)
		_, err := ec2Client.DeleteKeyPair(context.Background(), &ec2.DeleteKeyPairInput{
			KeyPairId: keyPair.KeyPairId,
		})
		if err != nil {
			return fmt.Errorf("unable to delete key pair %s: %w", *keyPair.KeyName, err)
		}
	}

	return nil
}

func randomSuffix() string {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

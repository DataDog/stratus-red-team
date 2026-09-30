package aws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

const keyPairNamePrefix = "key-stratus-red-team-"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.ec2-create-suspicious-keypair",
		FriendlyName: "Create an EC2 Key Pair with a Suspicious Name",
		Platform:     stratus.AWS,
		IsIdempotent: true, // each call creates a uniquely-named key pair
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
Creates an EC2 key pair with a name matching a known suspicious naming convention. Attackers
plant their own key pair so they can later launch or access EC2 instances without relying on
the credentials they used to gain initial access.

Warm-up: None.

Detonation:

- Call ec2:DescribeInstances filtered by the key name, to check whether the key pair is
  already in use.
- Call ec2:CreateKeyPair to create a new key pair whose name starts with "key".

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

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	keyPairName := keyPairNamePrefix + randomSuffix()

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

// revert looks up key pairs by the StratusRedTeam tag rather than by name,
// since the name is randomized per detonation and Go code cannot persist
// state between the detonate and revert calls (they run in separate processes).
func revert(_ map[string]string, providers stratus.CloudProviders) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())

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

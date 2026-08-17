package aws

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.impact.ec2-deregister-ami",
		FriendlyName: "Deregister an Amazon EC2 AMI",
		Description: `
Deregisters an EBS-backed AMI. Once deregistered, the AMI can no longer be used to launch new EC2 instances, disrupting recovery, deployment, autoscaling or replacement workflows that depend on it.

Warm-up:

- Create an EBS volume
- Create a snapshot from the volume
- Register an EBS-backed AMI from the snapshot

Detonation:

- Call <code>DeregisterImage</code> on the AMI

References:

- https://aws.amazon.com/blogs/security/what-the-march-2026-threat-technique-catalog-update-means-for-your-aws-environment/
- https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1485.A002.html
- https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeregisterImage.html

Note: the AMI's backing EBS snapshot is not deleted during detonation.
Cleanup still removes the remaining snapshot and volume after the AMI has been deregistered outside Terraform.
`,
		Detection: `
Through CloudTrail's <code>DeregisterImage</code> event, when an AMI is deregistered:

<pre><code>"eventSource": "ec2.amazonaws.com",
"eventName": "DeregisterImage",
"requestParameters": {
  "imageId": "ami-0b87ea1d007078d18",
  "deleteAssociatedSnapshots": false
}</code></pre>
`,
		Platform:           stratus.AWS,
		IsIdempotent:       false,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Impact},
		FrameworkMappings: []stratus.FrameworkMappings{
			{
				Framework: stratus.ThreatTechniqueCatalogAWS,
				Techniques: []stratus.TechniqueMapping{
					{
						Name: "Data Destruction: AMI Image Deletion",
						ID:   "T1485.A002",
						URL:  "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1485.A002.html",
					},
				},
			},
		},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

type ec2Deregisterer interface {
	DeregisterImage(context.Context, *ec2.DeregisterImageInput, ...func(*ec2.Options)) (*ec2.DeregisterImageOutput, error)
}

func deregisterAMI(ctx context.Context, client ec2Deregisterer, amiID string) error {
	_, err := client.DeregisterImage(ctx, &ec2.DeregisterImageInput{
		ImageId: aws.String(amiID),
	})
	if err != nil {
		return fmt.Errorf("unable to deregister AMI %s: %w", amiID, err)
	}
	return nil
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	amiID, ok := params["ami_id"]
	if !ok || amiID == "" {
		return errors.New("missing terraform output 'ami_id'")
	}

	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	log.Println("Deregistering AMI " + amiID)
	if err := deregisterAMI(context.Background(), ec2Client, amiID); err != nil {
		return err
	}

	log.Println("AMI " + amiID + " was deregistered")
	return nil
}

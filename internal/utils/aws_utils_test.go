package utils

import (
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsErrorRelatedToEbsEncryptionByDefault(t *testing.T) {
	assert.False(t, IsErrorDueToEBSEncryptionByDefault(nil))
	assert.False(t, IsErrorDueToEBSEncryptionByDefault(errors.New("foo")))
	assert.False(t, IsErrorDueToEBSEncryptionByDefault(&types.OperationNotPermittedException{}))
	assert.True(t, IsErrorDueToEBSEncryptionByDefault(
		errors.New("operation error EC2: ModifySnapshotAttribute, https response error StatusCode: 400, RequestID: 12f44aeb-7b3b-4488-ac46-a432d20cc7a9, api error OperationNotPermitted: Encrypted snapshots with EBS default key cannot be shared"),
	))
	assert.True(t, IsErrorDueToEBSEncryptionByDefault(
		errors.New("operation error EC2: ModifyImageAttribute, https response error StatusCode: 400, RequestID: 85f85eff-4114-4861-a659-f9aeea48d78b, api error InvalidParameter: Snapshots encrypted with the AWS Managed CMK can't be shared. Specify another snapshot"),
	))
}

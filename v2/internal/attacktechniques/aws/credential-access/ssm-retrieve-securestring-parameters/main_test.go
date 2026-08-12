package aws

import (
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/assert"
)

func TestParameterNamesWithPrefix(t *testing.T) {
	parameters := []types.ParameterMetadata{
		{Name: awsSdk.String("/credentials/team-stratus-red-team/credentials-0")},
		{Name: awsSdk.String("/credentials/stratus-red-team/credentials-1")},
		{Name: awsSdk.String("/application/database-password")},
	}

	testCases := []struct {
		name     string
		prefix   string
		expected []string
	}{
		{
			name:     "custom prefix",
			prefix:   "/credentials/team-stratus-red-team/",
			expected: []string{"/credentials/team-stratus-red-team/credentials-0"},
		},
		{
			name:     "default prefix",
			prefix:   "/credentials/stratus-red-team/",
			expected: []string{"/credentials/stratus-red-team/credentials-1"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expected, parameterNamesWithPrefix(parameters, testCase.prefix))
		})
	}
}

func TestDetonateRequiresSSMParameterPath(t *testing.T) {
	err := detonate(nil, nil)

	assert.EqualError(t, err, "missing required Terraform output: ssm_parameter_path")
}

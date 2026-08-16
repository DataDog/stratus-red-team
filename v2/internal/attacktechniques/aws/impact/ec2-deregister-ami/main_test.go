package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type fakeEC2Deregisterer struct {
	input *ec2.DeregisterImageInput
	err   error
}

func (f *fakeEC2Deregisterer) DeregisterImage(_ context.Context, input *ec2.DeregisterImageInput, _ ...func(*ec2.Options)) (*ec2.DeregisterImageOutput, error) {
	f.input = input
	return &ec2.DeregisterImageOutput{}, f.err
}

func TestDeregisterAMIUsesExpectedImage(t *testing.T) {
	client := &fakeEC2Deregisterer{}

	if err := deregisterAMI(context.Background(), client, "ami-0123456789abcdef0"); err != nil {
		t.Fatalf("deregisterAMI returned an unexpected error: %v", err)
	}
	if client.input == nil {
		t.Fatal("DeregisterImage was not called")
	}
	if got := awssdk.ToString(client.input.ImageId); got != "ami-0123456789abcdef0" {
		t.Fatalf("DeregisterImage ImageId = %q, want %q", got, "ami-0123456789abcdef0")
	}
}

func TestDeregisterAMIPropagatesAWSError(t *testing.T) {
	awsErr := errors.New("access denied")
	client := &fakeEC2Deregisterer{err: awsErr}

	err := deregisterAMI(context.Background(), client, "ami-0123456789abcdef0")
	if err == nil {
		t.Fatal("deregisterAMI returned nil, want an AWS error")
	}
	if !errors.Is(err, awsErr) {
		t.Fatalf("deregisterAMI error = %v, want wrapped AWS error", err)
	}
}

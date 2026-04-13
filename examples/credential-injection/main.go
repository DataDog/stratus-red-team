package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	stratusrunner "github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
	"github.com/google/uuid"
)

/*
This example injects explicit AWS credentials into the runner for the
detonation and revert phases.

Important: injected credentials are only used by the Detonate and Revert
functions (Go SDK calls). Terraform warmup and cleanup still use the
credentials from the environment (e.g. via aws-vault). This is because
Terraform is a separate subprocess with its own credential resolution.
A future change will allow forwarding injected credentials to Terraform
as well.

See README.md for setup instructions.
*/
func main() {
	accessKeyID := os.Getenv("ATTACK_AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("ATTACK_AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("ATTACK_AWS_SESSION_TOKEN")
	if accessKeyID == "" || secretKey == "" {
		fmt.Println("Set ATTACK_AWS_ACCESS_KEY_ID, ATTACK_AWS_SECRET_ACCESS_KEY, and ATTACK_AWS_SESSION_TOKEN")
		fmt.Println("See README.md for instructions")
		os.Exit(1)
	}

	correlationID := uuid.New()
	log.Printf("Correlation ID: %s", correlationID)

	// Build an AWS provider with the attacker role's credentials
	awsCfg := stratus.AWSConfigFromCredentials(accessKeyID, secretKey, sessionToken, &correlationID)
	awsProvider := stratus.NewAWSProvider(correlationID, stratus.WithAWSConfig(awsCfg))

	// Log the identity of the injected attacker credentials
	stsClient := sts.NewFromConfig(awsProvider.GetConnection())
	attackerIdentity, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatalf("Failed to verify attacker credentials: %v", err)
	}
	log.Printf("Attacker identity (detonate/revert): %s", *attackerIdentity.Arn)

	// Pre-populate CloudProvidersImpl with the explicit provider.
	// Note: only Detonate/Revert use this provider. Terraform warmup
	// and cleanup use the credentials from the environment instead.
	providerFactory := stratus.CloudProvidersImpl{
		UniqueCorrelationID: correlationID,
		AWSProvider:         awsProvider,
	}

	ttp := stratus.GetRegistry().GetAttackTechniqueByName("aws.defense-evasion.cloudtrail-stop")
	log.Printf("Technique: %s", ttp.ID)

	stratusRunner := stratusrunner.NewRunner(
		ttp,
		stratusrunner.StratusRunnerNoForce,
		stratusrunner.WithProviderFactory(providerFactory),
	)

	log.Println("Starting warmup (using environment credentials for Terraform)")
	_, err = stratusRunner.WarmUp()
	defer func() {
		log.Println("Starting cleanup")
		stratusRunner.CleanUp()
	}()
	if err != nil {
		log.Fatalf("Could not warm up TTP: %v", err)
	}
	log.Println("Warmup complete")

	fmt.Println("Press enter to detonate")
	fmt.Scanln()

	log.Printf("Starting detonation (using attacker identity: %s)", *attackerIdentity.Arn)
	err = stratusRunner.Detonate()
	if err != nil {
		log.Fatalf("Could not detonate TTP: %v", err)
	}
	log.Println("Detonation complete")

	log.Printf("Starting revert (using attacker identity: %s)", *attackerIdentity.Arn)
	err = stratusRunner.Revert()
	if err != nil {
		log.Fatalf("Could not revert TTP: %v", err)
	}
	log.Println("Revert complete")
}

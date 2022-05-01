package providers

import (
	"errors"
	"fmt"

	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/google/uuid"
)

const StratusUserAgent = "stratus-red-team"

var UniqueExecutionId = uuid.New()

func GetStratusUserAgent() string {
	return fmt.Sprintf("%s_%s", StratusUserAgent, UniqueExecutionId)
}

// EnsureAuthenticated ensures that the current user is properly authenticated against a specific platform
func EnsureAuthenticated(platform stratus.Platform) error {
	switch platform {
	case stratus.AWS:
		if !AWS().IsAuthenticatedAgainstAWS() {
			return errors.New("you are not authenticated against AWS, or you have not set your region. " +
				"Make sure you are authenticated against AWS, and you have a default region set in your AWS config " +
				"or environment (export AWS_DEFAULT_REGION=us-east-1)")
		}
	case stratus.Kubernetes:
		if !K8s().IsAuthenticated() {
			return errors.New("You do not have a kubeconfig set up, or you do not have proper permissions for " +
				"this cluster. Make sure you have proper credentials set in " + GetKubeConfigPath())
		}
	case stratus.Azure:
		if !Azure().IsAuthenticatedAgainstAzure() {
			return errors.New("Something went horribly wrong with the Azure auth.")
		}
	default:
		return errors.New("unhandled platform " + string(platform))
	}

	return nil
}
